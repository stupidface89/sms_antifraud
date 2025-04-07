import random
import datetime
import json
import uuid
import asyncio

from typing import NoReturn

from django.db.models import Count, F, ExpressionWrapper, FloatField, Min, Max, Subquery, Q
from rest_framework import generics, permissions, views, response, exceptions
from telegram_alarmer.main import telegram_send_message

from .models import (FirstName, LastName, Proxy, Task, Operation, ProxyProtocol, ModelDevice, AndroidBuildVersion,
                     City, Worker, OperationStatus)
from .serializers import (ProxySerializer, NameSerializer, TaskSerializer, OperationSerializer, DeviceSerializer,
                          CitySerializer, OperationCreateSerializer)


class GetProxy(generics.ListAPIView):
    queryset = Proxy.objects.all()
    serializer_class = ProxySerializer
    permission_classes = (permissions.AllowAny,)

    def get_queryset(self):
        return Proxy.objects.filter(is_active=True, proxy_type=ProxyProtocol.socks5)


class NameRandomRetrieve(views.APIView):
    queryset = FirstName.objects.all()
    serializer_class = NameSerializer
    permission_classes = (permissions.AllowAny,)

    def get_object(self):
        q = Q()
        if self.request.GET.get('country'):
            country_param = self.request.GET.get('country')
            q = Q(country__short_title__iexact=country_param)

        if self.request.GET.get('gender'):
            gender_param = self.request.GET.get('gender')
            q = q & Q(gender__iexact=gender_param)

        get_first_name = FirstName.objects.filter(q).order_by('?').first()
        get_last_name = LastName.objects.filter(q).order_by('?').first()

        return dict(first_name=get_first_name, last_name=get_last_name)

    def get(self, request):
        get_object = self.get_object()
        serializer = self.serializer_class(get_object)
        return response.Response(serializer.data)


class CityRandomRetrieve(views.APIView):
    queryset = City.objects.all()
    serializer_class = CitySerializer
    permission_classes = (permissions.AllowAny,)

    def get_object(self):
        return self.queryset.order_by('?').first()

    def get(self, request):
        """
            Рандомизируем разброс координат в рамках рандомно выбранного города
        """
        get_object = self.get_object()
        get_object.latitude = round(float(get_object.latitude) + random.uniform(0.005, 0.0075900), 6)
        get_object.longitude = round(float(get_object.longitude) + random.uniform(0.005, 0.0075900), 6)

        serializer = self.serializer_class(get_object)
        return response.Response(serializer.data)


class GetTask(views.APIView):
    permission_classes = (permissions.AllowAny,)

    def get_task(self):
        """
        Возвращаем задачу (сущность из связки токен-сервис), которая за сегодняшние сутки в процентном соотношении от
        общего необходимого суточного объема, по сравнению с другими задачами, на данный момент выполнена меньше всего.
        Таким образом получаем последовательное и равномерное выполнение всех активных задач.
        """

        now = datetime.datetime.now()

        # Получаем объект, с наименьшим, в относительном выражении, количеством выполненных операций за текущий час.
        # Делаем выборку по отношению выполненных задач к общему количеству задач, и сортируем по возрастанию,
        # а также исключаем выполненные задачи (ratio=1.0)
        get_task = (Task.objects
                    .filter(is_active=True)
                    .select_related('token').prefetch_related('proxies')
                    .annotate(all_operations=Count('operation', filter=Q(operation__time_created__year=now.year,
                                                                         operation__time_created__month=now.month,
                                                                         operation__time_created__day=now.day,
                                                                         operation__time_created__hour=now.hour)),

                              started=Count('operation', filter=Q(operation__time_created__year=now.year,
                                                                  operation__time_created__month=now.month,
                                                                  operation__time_created__day=now.day,
                                                                  operation__time_created__hour=now.hour) &
                                                                Q(operation__status='started')
                                            ),

                              ratio_all=ExpressionWrapper(F('all_operations') * 1.0 / (F('count') / 24), output_field=FloatField()),
                              ratio_started=ExpressionWrapper(F('started') * 1.0 / (F('count') / 24), output_field=FloatField()),
                              )
                    )
        # Исключаем из вывода те задачи, сумма операций которых, со статусом started, достигнула лимита операций в час
        get_task = get_task.exclude(ratio_started__gte=1.0).order_by('ratio_all')

        if get_task.exists():
            return get_task.first()

        else:
            return Task.objects.none()

    def operation_control(self, worker, task):
        serializer = OperationCreateSerializer(data={"worker": worker.id, "task": task.id}, many=False)
        if serializer.is_valid():
            return Operation.objects.create(worker=worker, task=task)

    def actualize_last_activity(self, hostname):
        # Обновляем время после запроса задачи воркером
        worker = Worker.objects.get_or_create(hostname=hostname)[0]
        worker.last_active = datetime.datetime.now()
        worker.save()
        return worker

    def post(self, request):
        try:
            get_body = json.loads(request.body)
        except json.JSONDecodeError:
            return response.Response({"success": "false", "error": {"message": "Failed Json, or body is empty"}}, status=400)

        if not get_body.get('worker'):
            return response.Response({"success": "false", "error": {"message": "Worker is empty value"}}, status=400)

        worker = self.actualize_last_activity(hostname=get_body.get('worker'))
        task = self.get_task()

        # Если была выдана задача, создаем операцию со статусом new
        if task:
            operation = self.operation_control(worker, task)
            task_serializer = TaskSerializer(task, many=False, context=operation)

            return response.Response(task_serializer.data, status=200)
        return response.Response({}, status=200)


class OperationSendStatus(views.APIView):
    serializer_class = OperationSerializer
    permission_classes = (permissions.AllowAny,)

    def check_series_failures(self, operation: Operation) -> NoReturn:
        """
        Метод проверяет, если за текущий час, количество операций со статусом NO_SMS >= 50% от общего необходимого
        числа операций за час, или >=30 шт., в зависимости от того что больше, то выключаем данную задачу, данный метод
        является предохранителем от блокировок со стороны сервисов
        """

        now = datetime.datetime.now()
        today_operations = operation.task.operation.select_related('task').filter(Q(time_created__year=now.year,
                                                                                    time_created__month=now.month,
                                                                                    time_created__day=now.day,
                                                                                    time_created__hour=now.hour))
        # Количество операций со статусом no_sms по текущей таске, за текущий час
        count_no_sms_operations = today_operations.filter(status=OperationStatus.no_sms).count()

        # Коэффициент - общий процент от операций за час со статусом no_sms, при достижении которого отключается задача.
        coefficient = 0.5

        # Если количество операций, которое необходимо выполнить за час, в соответствии с задачей, меньше 21,
        # что равняется 504 за сутки, то меняем коэффициент на 80%
        if int(operation.task.count/24) <= 21:
            coefficient = 0.8

        if count_no_sms_operations >= int(operation.task.count/24 * coefficient) or count_no_sms_operations >= 50:
            message = rf'Задача {operation.task} была выключена. \n За текущий час не доставлено смс - {count_no_sms_operations} шт.'
            asyncio.run(telegram_send_message(message=message))
            operation.task.is_active = False
            operation.task.save()

    def post(self, request):
        try:
            get_body = json.loads(request.body)

        except json.JSONDecodeError:
            return response.Response({"success": "false", "error": {"message": "Failed Json"}}, status=400)

        if not get_body.get('operation'):
            return response.Response({"success": "false", "error": {"message": "Operation id is empty"}}, status=400)

        try:
            operation_id = uuid.UUID(get_body.get('operation'))
        except ValueError:
            return response.Response({"success": "false", "error": {"message": "Wrong uuid value"}}, status=400)

        get_operation = Operation.objects.filter(id=operation_id).select_related('task').first()

        if not get_operation:
            return response.Response({"success": "false", "error": {"message": "Operation with such uuid does not exist"}}, status=400)

        serializer = OperationSerializer(data={"operation": get_body.get('operation'),
                                               "status": get_body.get('status')})

        if serializer.is_valid():
            if get_operation.status != serializer.data.get('status'):
                get_operation.status = serializer.data.get('status')
                get_operation.save()

            if serializer.data.get('status') == OperationStatus.no_sms:
                self.check_series_failures(operation=get_operation)

            return response.Response(serializer.data, status=200)
        return response.Response({"success": "false", "error": serializer.errors}, status=400)


class GetDevice(views.APIView):
    serializer_class = DeviceSerializer
    permission_classes = (permissions.AllowAny,)

    def get_object(self):
        # Дорогое решение взять рандомное значение, однако uuid не позволяет взять randint(Max(pk))
        get_device = ModelDevice.objects.order_by('?')[0]
        get_build = AndroidBuildVersion.objects.order_by('?')[0]

        return {'device': get_device,
                'build': get_build}

    def get(self, request):
        snippet = self.get_object()
        serializer = DeviceSerializer(snippet)
        return response.Response(serializer.data)


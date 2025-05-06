import random

from rest_framework import serializers, validators
from django.core.exceptions import ValidationError

from .models import (Proxy, FirstName, Task, Token, Operation, OperationType, ModelDevice, Manufacturer, MobileOperator,
                     City, Service, OperationStatus)


class ProxySerializer(serializers.ModelSerializer):
    country = serializers.SlugRelatedField('short_title', read_only=True)

    class Meta:
        model = Proxy
        fields = ('login', 'password', 'address', 'port', 'country', 'proxy_type')


class CitySerializer(serializers.ModelSerializer): # noqa
    region = serializers.StringRelatedField()

    class Meta:
        model = City
        fields = ('title', 'region', 'latitude', 'longitude')


class NameSerializer(serializers.Serializer): # noqa
    first_name = serializers.SerializerMethodField()
    last_name = serializers.SerializerMethodField()

    def get_first_name(self, obj):
        if obj.get('first_name') is not None:
            return obj.get('first_name').value

    def get_last_name(self, obj):
        if obj.get('last_name') is not None:
            return obj.get('last_name').value


class MobileOperatorSerializer(serializers.ModelSerializer):
    country = serializers.StringRelatedField()

    class Meta:
        model = MobileOperator
        fields = ('title', 'country', 'mcc', 'mnc', 'country_code')


class ServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = ('title', 'short_title')


class TokenSerializer(serializers.ModelSerializer):
    service = ServiceSerializer()
    operator = MobileOperatorSerializer()
    # service = ServiceSerializer()

    class Meta:
        model = Token
        fields = ('value', 'service', 'operator')


class TaskSerializer(serializers.ModelSerializer):
    token = TokenSerializer()
    proxies = ProxySerializer(many=True)
    operation = serializers.SerializerMethodField()

    class Meta:
        model = Task
        fields = ('type', 'operation', 'token', 'proxies')

    def get_operation(self, obj):
        return self.context.id

    def to_representation(self, instance):
        if not instance:
            return dict()
        return super(TaskSerializer, self).to_representation(instance)


class OperationCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Operation
        fields = ('worker', 'task')


class OperationSerializer(serializers.ModelSerializer):
    operation = serializers.UUIDField(source='id')

    class Meta:
        model = Operation
        fields = ('status', 'operation')

    def validate(self, data):
        values_list = [x[0] for x in OperationStatus.choices]

        if data.get('status') == 'new':
            raise ValidationError('Нельзя изменить статус операции на new')

        return super(OperationSerializer, self).validate(data)


class ManufacturerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Manufacturer
        fields = ('value',)


class ModelDeviceSerializer(serializers.ModelSerializer):
    manufacturer = serializers.StringRelatedField()

    class Meta:
        model = ModelDevice
        fields = ('manufacturer', 'retail_model', 'device', 'model')


class DeviceSerializer(serializers.Serializer): # noqa
    device = ModelDeviceSerializer()
    build_device = serializers.SerializerMethodField()

    @staticmethod
    def get_build_device(obj):
        device = obj.get('device')
        build = obj.get('build')
        android_version = 10
        user_type = 'user'
        tag = 'release-keys'

        # От балды собираем набор из цифр, который будет передаваться в качестве build_number
        build_number = str(random.randint(1, 9)) + str(random.randint(2010, 2021)) + str(random.randint(1, 12)) + str(random.randint(110, 999))

        # Собираем фингерпринт по схеме
        # $(PRODUCT_BRAND)/$(TARGET_PRODUCT)/$(TARGET_DEVICE):$(PLATFORM_VERSION)/$(BUILD_ID)/$(BF_BUILD_NUMBER):$(TARGET_BUILD_VARIANT)/$(BUILD_VERSION_TAGS)
        # ro.product.brand / ro.product.name / ro.product.device / ro.build.version.release / ro.build.id / ro.build.version.incremental:ro.build.type / ro.build.tags
        # samsung/starqlteue/starqlteue:10/QP1A.190711.020/G960U1UEU9FUE4:user/release-keys

        # Случайный набор из процессоров, ПОКА не имеет привязки к устройствам
        hardware_list = ['Helio P70', 'SC7731E', 'Kirin 710', 'Kirin 710F', 'MT6761', 'MT6765', 'Kirin 955', 'MSM8917']

        build_device = dict()
        hardware = random.choice(hardware_list)
        user_type = 'user'
        tag = 'release-keys'
        radio_version = str(1) + '.' + str(random.randint(0, 9)) + '.' + str(random.randint(0, 9)) + '.' + str(random.randint(0, 3))

        # Набросок хоста
        host = (f'h{random.randint(1, 9)}{random.choice([".", "-"])}'
                f'{device.manufacturer.__str__().lower()}-'
                f'{random.choice(["ota", "ttk", "svc", "ddp", "nom", "oop"])}'
                f'{random.choice(["-ru", "", "", "", "-nm", "-ch", "-au", "-gb", "-fr"])}'
                f'{random.choice([".org", ".com", ".net", ".bj", ".ch"])}')

        build_device['FINGERPRINT'] = (f'{device.manufacturer.__str__().lower()}/{device.device}/' 
                                       f'{device.device}:{android_version}/{build.build}/{build_number}:{user_type}/{tag}')

        # Нужно пересобрать и перепроверить возвращаемые параметры
        build_device['MANUFACTURER'] = device.manufacturer.__str__()
        build_device['MODEL'] = device.model
        build_device['PRODUCT'] = device.device
        build_device['BRAND'] = device.manufacturer.__str__().lower()
        build_device['HARDWARE'] = hardware    # Нужно проверять, что должен возвращать на самом деле
        build_device['DEVICE'] = device.device
        build_device['BOARD'] = hardware     # Нужно проверять, что должен возвращать на самом деле
        build_device['USER'] = device.device + f'-{user_type}'    # Нужно проверять, что должен возвращать на самом деле
        build_device['DISPLAY'] = f'{device.device}-{user_type} {android_version} {build.build} {tag}'
        build_device['ID'] = build.build
        build_device['TYPE'] = user_type
        build_device['TAGS'] = tag
        build_device['BOOTLOADER'] = 'unknown'
        build_device['CPU_ABI'] = 'arm64-v8a'
        build_device['CPU_ABI2'] = ''
        build_device['radio_version'] = radio_version     # Нужно проверять, что должен возвращать на самом деле
        build_device['HOST'] = host    # Нужно проверять, что должен возвращать на самом деле
        build_device['VERSION_INCREMENTAL'] = build_number

        return build_device

from django.db import models

import uuid


class AndroidVersionChoice(models.TextChoices):
    android9 = 'Android9'
    android10 = 'Android10'
    android11 = 'Android11'


class GenderChoice(models.TextChoices):
    male = 'male'
    female = 'female'


class CountriesTitle(models.TextChoices):
    russia = 'RU'
    ukraine = 'UA'
    georgia = 'GE'
    belarus = 'BY'
    europe = 'EU'


class OperationStatus(models.TextChoices):
    """
        new = Присваивается по создании объекта, не несет бизнесс нагрузки
        started = Присваивается после запроса номера телефона
        requested = Присваивается после того, как была запрошена смс
        no_sms = Присваивается если смс не пришла
        got_sms = Присваивается, если смс была получена
        failed = Присваивается, если сценарий был выполнен не до конца
        completed = Присваивается, если сценарий был выполнен полностью
    """
    new = 'new'
    started = 'started'
    requested = 'requested'
    no_sms = 'no_sms'
    got_sms = 'got_sms'
    failed = 'failed'
    completed = 'completed'


class OperationType(models.TextChoices):
    """
    Тип операции, которая была проделана для запроса смс у сервиса
    """
    registration = 'reg'
    authentication = 'auth'
    milking = 'milk'


class Country(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    title = models.CharField(max_length=100, blank=False, null=True, choices=CountriesTitle.choices)
    short_title = models.CharField(max_length=20, blank=False, null=True)

    def __str__(self):
        return self.title

    class Meta:
        verbose_name_plural = 'Countries'


class ProxyProtocol(models.TextChoices):
    socks5 = 'socks5'
    https = 'https'


class ProxyType(models.TextChoices):
    mobile = 'mobile'
    static = 'static'


class Service(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    title = models.CharField(max_length=50, blank=False, null=True)
    short_title = models.CharField(max_length=10, blank=False, null=True)

    def __str__(self):
        return self.title.__str__()


class MobileOperator(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    title = models.CharField(max_length=100, blank=False, null=True)
    country = models.ForeignKey(Country, on_delete=models.SET_NULL, max_length=3, blank=False, null=True)
    mcc = models.CharField(max_length=20, blank=False, null=True, verbose_name="Mobile Country Code")
    mnc = models.CharField(max_length=20, blank=False, null=True, verbose_name="Mobile Network Code")
    country_code = models.CharField(max_length=5, blank=False, null=True, verbose_name="Country short name")

    class Meta:
        db_table = 'workers_mobile_operator'

    def __str__(self):
        return self.title


class FirstName(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    value = models.CharField(max_length=100, blank=False, null=True, verbose_name='Имя', )
    gender = models.CharField(max_length=15, null=False, blank=False,
                              choices=GenderChoice.choices,
                              default=GenderChoice.male)
    country = models.ManyToManyField(Country, through='FirstNameCountry', max_length=3, blank=False)

    def __str__(self):
        return self.value

    class Meta:
        unique_together = ['value', 'gender']
        db_table = 'workers_first_name'


class FirstNameCountry(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    first_name = models.ForeignKey(FirstName, on_delete=models.CASCADE, blank=False, null=True)
    country = models.ForeignKey(Country, on_delete=models.CASCADE, blank=False, null=True)

    class Meta:
        unique_together = ['first_name', 'country']
        db_table = 'workers_first_name_country'


class LastName(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    value = models.CharField(max_length=100, blank=False, null=True, verbose_name='Фамилия')
    gender = models.CharField(max_length=15, null=False, blank=False, choices=GenderChoice.choices,
                              default=GenderChoice.male)
    country = models.ManyToManyField(Country, through='LastNameCountry', max_length=3, blank=False)

    def __str__(self):
        return self.value

    class Meta:
        unique_together = ['value', 'gender']
        db_table = 'workers_last_name'


class LastNameCountry(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    last_name = models.ForeignKey(LastName, on_delete=models.CASCADE, blank=False, null=True)
    country = models.ForeignKey(Country, on_delete=models.CASCADE, blank=False, null=True)

    class Meta:
        unique_together = ['last_name', 'country']
        db_table = 'workers_last_name_country'


class BaseAccount(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    operation_id = models.CharField(max_length=100, blank=True, null=False, unique=True)
    phone_number = models.CharField(max_length=30, blank=False, null=True, unique=True)
    first_name = models.CharField(max_length=50, blank=False, null=True)
    last_name = models.CharField(max_length=50, blank=False, null=True)
    birth_day = models.DateField(blank=False, null=True)
    gender = models.CharField(max_length=15, null=False, blank=False,
                              choices=GenderChoice.choices,
                              default=GenderChoice.male)
    country = models.ForeignKey(Country, on_delete=models.CASCADE, blank=False, null=True)
    city = models.CharField(max_length=90, blank=True, null=False)
    base_latitudes = models.CharField(max_length=100, blank=False, null=True)


class Proxy(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    login = models.CharField(max_length=50, blank=False, null=True)
    password = models.CharField(max_length=50, blank=False, null=True)
    address = models.CharField(max_length=50, blank=False, null=True)
    port = models.CharField(max_length=10, blank=False, null=True)
    country = models.ForeignKey(Country, on_delete=models.SET_NULL, blank=False, null=True)
    proxy_protocol = models.CharField(max_length=20, blank=False, null=True, choices=ProxyProtocol.choices)
    proxy_type = models.CharField(max_length=20, blank=False, null=True, choices=ProxyType.choices)
    last_active_date = models.DateTimeField(auto_now=True, blank=True, null=True)
    is_active = models.BooleanField(default=False)

    class Meta:
        unique_together = ['login', 'password', 'address', 'port']
        verbose_name_plural = 'Proxies'

    def __str__(self):
        self.title = f'{self.country} / {self.proxy_type.__str__().upper()} - {self.login}:{self.password}@{self.address}:{self.port}'
        return self.title


class Token(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    value = models.CharField(max_length=50, blank=False, null=True, unique=True)
    service = models.ForeignKey(Service, on_delete=models.SET_NULL, blank=False, null=True, related_name='service')
    country = models.ForeignKey(Country, on_delete=models.SET_NULL, max_length=3, blank=False, null=True)
    operator = models.ForeignKey(MobileOperator, on_delete=models.SET_NULL, blank=False, null=True)
    description = models.TextField(max_length=200, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ['service', 'value', 'operator']

    def __str__(self):
        return self.service.__str__() + " / " + self.operator.__str__() + " / " + self.country.__str__()


class Task(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    token = models.OneToOneField(Token, on_delete=models.CASCADE, blank=False, null=True, related_name='token')
    count = models.PositiveIntegerField()
    date_created = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=False)
    type = models.CharField(max_length=50, blank=False, null=True, choices=OperationType.choices,
                            verbose_name='Тип операции')
    description = models.TextField(max_length=1000, blank=True)
    proxies = models.ManyToManyField(Proxy)

    def __str__(self):
        return str(self.count) + " / " + self.token.service.title.__str__() + " / " + self.token.operator.__str__()


class Worker(models.Model):
    hostname = models.CharField(max_length=100, unique=True)
    last_active = models.DateTimeField(auto_now=True, blank=False, null=True)
    ipaddress = models.GenericIPAddressField(blank=True, null=True)

    def __str__(self):
        return self.hostname


class Operation(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    time_created = models.DateTimeField(auto_now_add=True, blank=True, null=False)
    time_last_change = models.DateTimeField(auto_now=True, blank=True, null=False)
    task = models.ForeignKey(Task, on_delete=models.CASCADE, blank=False, null=True, related_name='operation')
    worker = models.ForeignKey(Worker, on_delete=models.DO_NOTHING, blank=False, null=True)
    status = models.CharField(max_length=50, blank=False, null=False, default=OperationStatus.new,
                              choices=OperationStatus.choices)


class AndroidBuildVersion(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    build = models.CharField(max_length=50, blank=False, null=True, unique=True)
    tag = models.CharField(max_length=80, blank=False, null=True, db_index=True, verbose_name='Тэг сборки')
    version = models.CharField(max_length=50, blank=False, null=True, choices=AndroidVersionChoice.choices,
                               verbose_name='Версия андройд')

    def __str__(self):
        return self.build


class Manufacturer(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    title = models.CharField(max_length=100, blank=False, db_index=True)
    value = models.CharField(max_length=100, blank=False, unique=True)

    def __str__(self):
        return self.title


class ModelDevice(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    manufacturer = models.ForeignKey(Manufacturer, on_delete=models.CASCADE, blank=False)
    retail_model = models.CharField(max_length=100, blank=False, null=True, unique=True)
    device = models.CharField(max_length=50, blank=False, null=True)
    model = models.CharField(max_length=50, blank=False, null=True, unique=True)

    class Meta:
        unique_together = ['manufacturer', 'retail_model']
        db_table = 'workers_model_device'

    def __str__(self):
        return self.manufacturer.__str__() + ' ' + self.retail_model


class Region(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    title = models.CharField(max_length=200, blank=False, null=True, unique=True)
    country = models.ForeignKey(Country, blank=False, null=True, on_delete=models.SET_NULL)

    def __str__(self):
        return self.title


class City(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    title = models.CharField(max_length=200, blank=False, null=True)
    region = models.ForeignKey(Region, blank=False, null=True, on_delete=models.SET_NULL)
    latitude = models.CharField(max_length=30, blank=False, null=True)
    longitude = models.CharField(max_length=30, blank=False, null=True)

    class Meta:
        unique_together = ['title', 'region']

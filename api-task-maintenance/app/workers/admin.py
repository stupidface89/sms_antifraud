from django.contrib import admin
from .models import (Proxy, AndroidBuildVersion, Manufacturer, Task, Token, Service, Operation, FirstName, LastName, Country,
                     FirstNameCountry, LastNameCountry, ModelDevice, MobileOperator, City, Worker)


class FirstNameInline(admin.TabularInline):
    model = FirstNameCountry


class LastNameInline(admin.TabularInline):
    model = LastNameCountry


class ProxiesInline(admin.TabularInline):
    model = Task.proxies.through


@admin.register(City)
class CityAdmin(admin.ModelAdmin):
    list_select_related = ('region__country',)
    list_display = ('title', 'region', 'latitude', 'longitude')


@admin.register(ModelDevice)
class ModelDeviceAdmin(admin.ModelAdmin):
    pass


@admin.register(Proxy)
class ProxyAdmin(admin.ModelAdmin):
    list_display = ('country', 'proxy_type', 'proxy_protocol', 'address', 'port', 'is_active', 'last_active_date')
    inlines = (ProxiesInline,)


@admin.register(AndroidBuildVersion)
class AndroidBuildVersionAdmin(admin.ModelAdmin):
    list_display = ('build', 'tag', )


@admin.register(Manufacturer)
class DeviceBuildAdmin(admin.ModelAdmin):
    pass


@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    list_display = ('operator', 'service', 'country', 'description', 'is_active')


@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ('id', 'token', 'count', 'is_active', )
    inlines = (ProxiesInline,)


@admin.register(MobileOperator)
class MobileOperatorAdmin(admin.ModelAdmin):
    pass


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    pass


@admin.register(Operation)
class OperationsAdmin(admin.ModelAdmin):
    list_display = ('id', 'time_created', 'task', 'worker', 'status')
    date_hierarchy = 'time_created'
    list_filter = ('task',)
    list_per_page = 25
    
    # def has_add_permission(self, request):
    #     return False
    #
    # def has_delete_permission(self, request, obj=None):
    #     return False
    #
    # def has_change_permission(self, request, obj=None):
    #     return False


@admin.register(FirstName)
class FirstNameAdmin(admin.ModelAdmin):
    inlines = (FirstNameInline,)


@admin.register(LastName)
class LastNameAdmin(admin.ModelAdmin):
    inlines = (LastNameInline,)


@admin.register(Country)
class CountryAdmin(admin.ModelAdmin):
    list_display = ('title', 'short_title')


@admin.register(Worker)
class WorkerAdmin(admin.ModelAdmin):
    list_display = ('hostname', 'ipaddress', 'last_active')

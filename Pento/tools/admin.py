from django.contrib import admin
from .models import ToolLog

@admin.register(ToolLog)
class ToolLogAdmin(admin.ModelAdmin):
    list_display = ('tool_name', 'scan_date')
    search_fields = ('tool_name',)

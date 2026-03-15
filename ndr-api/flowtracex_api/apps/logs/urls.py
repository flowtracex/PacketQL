from django.urls import path
from .views import (
    LogSearchView,
    LogAnalyticsView,
    LogLiveStreamView,
    LogPcapUploadView,
    LogPcapListView,
    DataSourceListView,
    CurrentDataSourceView,
    DataSourceSummaryView,
    TableSchemaView,
    ResetDataView,
    IngestStatusView,
    PipelineHealthView,
    SchemaGuideView,
)

urlpatterns = [
    path('logs/search', LogSearchView.as_view(), name='log_search'),
    path('logs/analytics', LogAnalyticsView.as_view(), name='log_analytics'),
    path('logs/live', LogLiveStreamView.as_view(), name='log_live'),
    path('logs/upload-pcap', LogPcapUploadView.as_view(), name='log_upload_pcap'),
    path('logs/pcap-files', LogPcapListView.as_view(), name='log_pcap_files'),
    path('logs/data-sources', DataSourceListView.as_view(), name='data_sources'),
    path('logs/current-source', CurrentDataSourceView.as_view(), name='current_source'),
    path('logs/source-summary', DataSourceSummaryView.as_view(), name='source_summary'),
    path('logs/table-schema', TableSchemaView.as_view(), name='table_schema'),
    path('logs/reset-data', ResetDataView.as_view(), name='reset_data'),
    path('logs/ingest-status', IngestStatusView.as_view(), name='ingest_status'),
    path('logs/pipeline-health', PipelineHealthView.as_view(), name='pipeline_health'),
    path('logs/schema-guide', SchemaGuideView.as_view(), name='schema_guide'),
]

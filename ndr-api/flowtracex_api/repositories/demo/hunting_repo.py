from ..base.hunting_repo import HuntingRepository
from apps.hunting.models import Hunt
from apps.hunting.serializers import HuntSerializer
from django.core.paginator import Paginator
from django.utils import timezone


class DemoHuntingRepository(HuntingRepository):
    def _prod(self):
        from repositories.production.hunting_repo import ProductionHuntingRepository
        return ProductionHuntingRepository()

    def list_hunts(self, filters, page=1, limit=10):
        queryset = Hunt.objects.all().order_by('-created_at')

        if filters.get('search'):
            queryset = queryset.filter(name__icontains=filters['search'])
        if filters.get('status'):
            queryset = queryset.filter(status=filters['status'])

        paginator = Paginator(queryset, limit)
        page_obj = paginator.get_page(page)
        return {
            "hunts": HuntSerializer(page_obj.object_list, many=True).data,
            "total": paginator.count,
            "page": page_obj.number,
            "page_count": paginator.num_pages
        }

    def save_hunt(self, data, user):
        return None

    def get_hunt(self, hunt_id):
        try:
            hunt = Hunt.objects.get(pk=hunt_id)
            return HuntSerializer(hunt).data
        except Hunt.DoesNotExist:
            return None

    def run_hunt(self, query_type, params):
        return self._prod().run_hunt(query_type, params)

    def get_hunt_runs(self, hunt_id):
        return self._prod().get_hunt_runs(hunt_id)

    def get_hunt_run_result(self, run_id):
        return self._prod().get_hunt_run_result(run_id)

    def delete_hunt(self, hunt_id):
        return False

    def get_categories(self):
        return self._prod().get_categories()

    def get_templates(self, search, category):
        return self._prod().get_templates(search, category)

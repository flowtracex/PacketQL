from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from services.rule_service import RuleService

class RuleListView(APIView):

    def get(self, request):
        page = int(request.query_params.get('page', 1))
        limit = int(request.query_params.get('limit', 10))
        filters = request.query_params.dict()
        
        service = RuleService()
        data = service.list_rules(filters, page, limit)
        return Response(data)

    def post(self, request):
        service = RuleService()
        data = service.create_rule(request.data, request.user)
        if data:
            return Response(data, status=status.HTTP_201_CREATED)
        return Response(status=status.HTTP_400_BAD_REQUEST)

class RuleDetailView(APIView):

    def get(self, request, pk):
        service = RuleService()
        data = service.get_rule(pk)
        if data:
            return Response(data)
        return Response(status=status.HTTP_404_NOT_FOUND)

    def put(self, request, pk):
        service = RuleService()
        data = service.update_rule(pk, request.data)
        if data:
            return Response(data)
        return Response(status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, pk):
        service = RuleService()
        if service.delete_rule(pk):
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(status=status.HTTP_404_NOT_FOUND)

class RuleAnalyticsView(APIView):

    def get(self, request):
        service = RuleService()
        data = service.get_analytics()
        return Response(data)

class RuleSchemaFieldsView(APIView):

    def get(self, request):
        service = RuleService()
        data = service.get_schema_fields()
        return Response(data)

class RuleSchemaValuesView(APIView):

    def get(self, request):
        field = request.query_params.get('field')
        service = RuleService()
        data = service.get_schema_values(field)
        return Response(data)

class RuleTemplatesView(APIView):

    def get(self, request):
        search = request.query_params.get('search')
        category = request.query_params.get('category')
        service = RuleService()
        data = service.get_templates(search, category)
        return Response(data)

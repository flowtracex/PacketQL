from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from services.usecase_service import UseCaseService

class UseCaseListView(APIView):

    def get(self, request):
        service = UseCaseService()
        data = service.list_usecases()
        return Response(data)

class UseCaseDetailView(APIView):

    def get(self, request, pk):
        service = UseCaseService()
        data = service.get_usecase(pk)
        if data:
            return Response(data)
        return Response(status=status.HTTP_404_NOT_FOUND)

class SignalListView(APIView):

    def get(self, request):
        service = UseCaseService()
        data = service.list_signals()
        return Response(data)

class SignalDetailView(APIView):

    def get(self, request, pk):
        service = UseCaseService()
        data = service.get_signal(pk)
        if data:
            return Response(data)
        return Response(status=status.HTTP_404_NOT_FOUND)

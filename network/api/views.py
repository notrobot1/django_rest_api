from django.views import generic
from rest_framework.authtoken.models import Token
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import generics, permissions, status
from rest_framework.permissions import SAFE_METHODS, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.exceptions import PermissionDenied
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from rest_framework import permissions
from django.http import HttpResponse, Http404
from .models import *
from .serializers import *
# Create your views here.



# def index(request):
#     request.session
#     auth_user_id = request.user.id
#     num_books = User.objects.filter(id=auth_user_id)
#
#     return render(
#         request,
#         'api/user_detail.html',
#         context={'user_detail':num_books},
#     )

class DetailListView(generic.DetailView):
    model = User
    #paginate_by = 10
    def get_queryset(self):
        if len(User.objects.filter(id=self.kwargs['pk'])) != 0:
            return User.objects.filter(id=self.kwargs['pk'])
        else:
            raise Http404("Book does not exist")

class UserListView(generic.ListView):
    model = User
    paginate_by = 10
    print(User.objects)
    # def get_queryset(self):
    #     if len(User.objects) != 0:
    #         return User.objects
    #     else:
    #         raise Http404("Book does not exist")


class ExecutorListView(generics.ListAPIView):
    User = get_user_model()
    queryset = User.objects.all()
    serializer_class = UserSerializer1


    #filter_class = ProductFilter

class Logout(APIView):

    def get(self, request, format=None):
        request.user.auth_token.delete()
        return HttpResponse(status=200)


class ExecutorRetrieveView(generics.RetrieveAPIView):
    """
    Получаем пользователя
    """
    User = get_user_model()
    queryset = User.objects.all()
    serializer_class = ExecutorSerializer



class BlocklistPermission(permissions.BasePermission):
    """
    Global permission check for blocked IPs.
    """

    def has_object_permission(self, request, view, obj):

        id = request.META['PATH_INFO'].split("/")[-1]

        if int(request.user.id) == int(id):
            return True
        else:
            return False
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        #if request.method in permissions.SAFE_METHODS:


        # Instance must have an attribute named `owner`.
        #return obj.owner == request.user






# class ExecutorUpdateView(generics.UpdateAPIView):
#
#     User = get_user_model()
#     queryset = User.objects.all()
#     serializer_class = CreateExecutorSerializer
#     print(serializer_class.data)
#     permission_classes = [BlocklistPermission]
#
#
#     # def get_object(self, pk):
#     #     try:
#     #         return User.objects.get(pk=pk)
#     #     except Exception as e:
#     #         return Response({'message': str(e)})
#     #
#     def get_object(self, queryset=None):
#         obj = self.request.user
#         return obj
#     def put(self, request, pk, format=None, *args, **kwargs):
#         self.object = self.get_object()
#
#         self.update(request, *args, **kwargs)
#         self.object.set_password(request.data.get("password"))
#         self.object.save()
#         content = {'user_update': "ok"}
#         return Response(content)
#     #     self.object = self.get_object()
#     #
#     #     old_password = serializer_class.data.get("old_password")
#     #         if not self.object.check_password(old_password):
#     #             return Response({"old_password": ["Wrong password."]},
#     #                             status=status.HTTP_400_BAD_REQUEST)
#     #         # set_password also hashes the password that the user will get
#     #         self.object.set_password(serializer.data.get("new_password"))
#     #         self.object.save()
#         #return Response('ok')


class ChangePasswordView(generics.UpdateAPIView):
    User = get_user_model()

    serializer_class = ChangePasswordSerializer

    def update(self, request, *args, **kwargs):

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        # if using drf authtoken, create a new token
        if hasattr(user, 'auth_token'):
            user.auth_token.delete()
        token, created = Token.objects.get_or_create(user=user)
        # return new token
        return Response({'token': token.key}, status=status.HTTP_200_OK)

class UpdateProfileView(generics.UpdateAPIView):

    queryset = User.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = UpdateUserSerializer



class DelA(APIView):
    """
    Retrieve, update or delete a snippet instance.
    """
    User = get_user_model()

    # def get_object(self):
    #
    #     try:
    #         return User.objects.get(pk=10)
    #     except User.DoesNotExist:
    #         raise Http404



    def delete(self, request,  format=None):
        user = request.user
        print(user)
        #snippet = self.get_object(pk)
        snippet = user
        snippet.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)



# class UserViewSet(APIView):
#     queryset = User.objects.all()
#     serializer_class = UserReg




class Register(generics.CreateAPIView):
    User = get_user_model()
    queryset = User.objects.all()
    serializer_class = UserReg
    # def post(self, request):
    #     user = User.objects.create(
    #             username=request.data.get('username'),
    #     )
    #     user.set_password(str(request.data.get('password')))
    #     user.save()
    #     return Response({"status":"success","response":"User Successfully Created"}, status=status.HTTP_201_CREATED)
from django.urls import path, include, re_path
from rest_framework.authtoken.views import obtain_auth_token
# from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
# from rest_framework_simplejwt.views import TokenObtainSlidingView, TokenRefreshSlidingView
from django.conf.urls import url
from .views import *

urlpatterns = [
    #path('auth/', include('djoser.urls')),
    path('', UserListView.as_view()),
    re_path(r'^id/(?P<pk>\d+)$', DetailListView.as_view(), name='books'),
    path('auth/reg', Register.as_view()),
    path('auth/token', obtain_auth_token, name='token'),
    path('auth/logout', Logout.as_view()),
    #
    path('user/<int:pk>', ExecutorRetrieveView.as_view()),
    path('user/all', ExecutorListView.as_view()),
    path('user/password', ChangePasswordView.as_view(), name="item_category"),
    path('user/update/profile/<int:pk>', UpdateProfileView.as_view(), name='auth_update_profile'),
    path('user/delete', DelA.as_view(), name='auth_update_profile'),
]




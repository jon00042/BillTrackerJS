from django.urls import path
from . import views

app_name = 'main'

urlpatterns = [
    path('', views.index, name='index'),
    path('register', views.register, name='register'),
    path('register/', views.register, name='register'),
    path('login', views.login, name='login'),
    path('login/', views.login, name='login'),
    path('logout', views.logout, name='logout'),
    path('logout/', views.logout, name='logout'),
    path('authenticate_ajax/<str:auth_for>', views.authenticate_ajax, name='authenticate_ajax'),
    path('data_ajax', views.data_ajax, name='data_ajax'),
]


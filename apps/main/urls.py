from django.urls import path
from . import views

app_name = 'main'

urlpatterns = [
    path('', views.index, name='index'),
    path('data', views.data, name='data'),
    path('register', views.register, name='register'),
    path('login', views.login, name='login'),
    path('logout', views.logout, name='logout'),
    path('authenticate_ajax/<str:auth_for>', views.authenticate_ajax, name='authenticate_ajax'),
]


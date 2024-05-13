from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.loginPage, name='login'),
    path('logout/', views.logoutUser, name='logout'),
    path('register/', views.registerPage, name='register'),
    path('', views.home, name='home'),
    path('profile/<str:pk>/', views.userProfile, name='user-profile'),

    path('conversation/<str:pk>/', views.conversation, name='conversation'),
    path('create-conversation/', views.createConversation, name='create-conversation'),

    path('delete-conversation/<str:pk>/', views.deleteConversation, name='delete-conversation'),
    path('delete-message/<str:pk>/', views.deleteMessage, name='delete-message'),
    path('update-user/', views.updateUser, name='update-user'),
]

from django.contrib import admin

from .models import Conversation, Message, Key

# Register your models here.


admin.site.register(Message)
admin.site.register(Conversation)
admin.site.register(Key)

from django.db import models
from django.contrib.auth.models import User


class Conversation(models.Model):
    name = models.CharField(max_length=200)
    participants = models.ManyToManyField(User, related_name='participants', blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    aes_key = models.BinaryField(null=True, blank=True)  # Add a field to store AES key

    class Meta:
        ordering = ['timestamp', 'name']

    def __str__(self):
        participant_names = [participant.username for participant in self.participants.all()]
        participant_names.sort()
        return ' - '.join(participant_names)


class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sender')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='receiver')
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE)
    content = models.TextField()
    encrypted_content = models.CharField(max_length=200)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.content[0:50]
    
class Key(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='keys')
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='keys')
    aes_key = models.BinaryField()
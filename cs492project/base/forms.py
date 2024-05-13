from django import forms
from django.contrib.auth.models import User
from .models import Conversation


class ConversationForm(forms.ModelForm):
    participant = forms.ModelChoiceField(
        queryset=User.objects.all(), required=False,
        label="Select Partner")

    class Meta:
        model = Conversation
        fields = ['participant']

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)  # Extracting user from kwargs
        super(ConversationForm, self).__init__(*args, **kwargs)

        if self.instance.pk:  # If instance exists (edit mode)
            self.fields['participant'].queryset = User.objects.exclude(
                id=self.user.id).exclude(id__in=self.instance.participants.all())
        else:  # If creating new instance
            self.fields['participant'].queryset = User.objects.exclude(id=self.user.id)

    def save(self, commit=True):
        conversation = super(ConversationForm, self).save(commit=False)
        if not self.instance.pk:  # If creating new instance
            conversation.save()
            conversation.participants.add(self.user)
        if self.aes_key:
            conversation.aes_key = self.aes_key
        if commit:
            conversation.save() 
            participant = self.cleaned_data.get('participant', None)
            if participant and participant != self.user:
                conversation.participants.add(participant)
                conversation.name = f"{self.user.username} - {participant.username}"

            self.save_m2m()

        return conversation

class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.http import HttpResponse
from django.shortcuts import render, redirect
from .models import Conversation, Message, Key
from .forms import ConversationForm, UserForm

from Crypto.Random import get_random_bytes
from .aes import AES


# Create your views here.
def loginPage(request):
    page = 'login'

    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        username = request.POST.get('username').lower()
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, 'Username or Password does not exist')

    context = {'page': page}
    return render(request, 'base/login_register.html', context)


@login_required(login_url='login')
def logoutUser(request):
    logout(request)
    return redirect('home')


def registerPage(request):
    form = UserCreationForm()

    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.username = user.username.lower()
            user.save()
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, 'An error occurred during registration')

    context = {'form': form}
    return render(request, 'base/login_register.html', context)


def home(request):
    cs = Conversation.objects.filter(participants=request.user.id)
    c_count=0
    friend_list = []
    context = {'conversations': cs, 'conversation_count': c_count, 'friends': friend_list}
    return render(request, 'base/home.html', context)


@login_required(login_url='login')
def conversation(request, pk):
    receiver = None
    c = Conversation.objects.get(id=pk)
    participants = c.participants.all()
    print(c.aes_key)
    cipher= AES(c.aes_key)
    for participant in participants:
        if participant.id != request.user.id:
            receiver = participant
    ms = c.message_set.all().order_by('-timestamp')

    if request.method == 'POST':
        content = request.POST.get('content')
        ciphertext = cipher.aes_encrypt(content.encode('utf-8'))
        message = Message.objects.create(
            sender=request.user,
            receiver=receiver,
            conversation=c,
            content=content,
            encrypted_content=ciphertext
        )
        return redirect('conversation', pk=c.id)

    context = {'conversation': c, 'participants': participants, 'conversation_messages': ms}
    return render(request, 'base/conversation.html', context)


def userProfile(request, pk):
    user = User.objects.get(id=pk)
    context = {'user': user}
    print(context)
    return render(request, 'base/profile.html', context)


@login_required(login_url='login')
def createConversation(request):
    if request.method == 'POST':
        # Create an AES key
        aes_key = get_random_bytes(16)

        form = ConversationForm(request.POST, user=request.user)
        if form.is_valid():
            # Save AES key for Conversation model
            form.aes_key=aes_key
            form.save()
            c = form.instance
            # Create Key instances for participants
            participants = c.participants.all()
            for p in participants:
                key = Key.objects.create(
                    user=p,
                    conversation=c,
                    aes_key=aes_key
                )
            return redirect('home')
    else:
        form = ConversationForm(user=request.user)
    context = {'form': form}
    return render(request, 'base/conversation_form.html', context)


@login_required(login_url='login')
def deleteConversation(request, pk):
    c = Conversation.objects.get(id=pk)

    is_participants = c.participants.filter(id=request.user.id).exists()
    if not is_participants:
        return HttpResponse('You are not allowed here!!')

    if request.method == 'POST':
        c.delete()
        return redirect('home')

    context = {'obj': c}
    return render(request, 'base/delete.html', context)

@login_required(login_url='login')
def deleteMessage(request, pk):
    message = Message.objects.get(id=pk)

    if request.user != message.sender:
        return HttpResponse('You are not allowed here!!')

    if request.method == 'POST':
        message.delete()
        return redirect('home')

    context = {'obj': message}
    return render(request, 'base/delete.html', context)

@login_required(login_url='login')
def updateUser(request):
    user = request.user
    form = UserForm(instance=user)

    if request.method == 'POST':
        form = UserForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            return redirect('user-profile', pk=user.id)

    context = {'form': form}
    return render(request, 'base/update-user.html', context)

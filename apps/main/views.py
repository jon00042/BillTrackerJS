import apps.main.models as m
import bcrypt
import django
import json

from django.contrib import messages
from django.core import serializers
from django.http import JsonResponse
from django.shortcuts import redirect, render
from pprint import pprint

def get_logged_in_user(request):
    if ('user_id' not in request.session):
        return None
    try:
        return m.User.objects.get(id=request.session['user_id'])
    except m.User.DoesNotExist:
        pass
    except Exception as ex:
        print(ex)
    return None

def index(request):
    if (not get_logged_in_user(request)):
        return redirect('main:login')
    return render(request, 'main/index.html')

def register(request):
    if (get_logged_in_user(request)):
        return redirect('main:index')
    return render(request, 'main/register.html')

def login(request):
    if (get_logged_in_user(request)):
        return redirect('main:index')
    return render(request, 'main/login.html')

def logout(request):
    request.session.clear()
    return redirect('main:index')

def authenticate_ajax(request, auth_for):
    if (request.method != 'POST'):
        return JsonResponse({ 'errors': [ request.method + ' not permitted!' ] }, status=400)
    if (get_logged_in_user(request)):
        return JsonResponse({ 'errors': [ 'User already logged in!' ] }, status=400)
    if (auth_for == 'register' and register_user(request)):
        return JsonResponse({ 'url': redirect('main:login').url })
    elif (auth_for == 'login' and login_user(request)):
        return JsonResponse({ 'url': redirect('main:index').url })
    errors = []
    for message in messages.get_messages(request):
        errors.append(str(message))
    return JsonResponse({ 'errors': errors }, status=400)

def check_ajax_fields(request, fields):
    for field in fields:
        if (field in request.POST):
            if (len(request.POST[field]) < 1):
                messages.error(request, '{} is empty in ajax request!'.format(field))
        else:
            messages.error(request, '{} is missing in ajax request!'.format(field))
    return len(messages.get_messages(request)) == 0

def register_user(request):
    if (not check_ajax_fields(request, ['email', 'fullname', 'sha_pwd'])):
        return False
    sha_pwd_bytes = request.POST['sha_pwd'].encode('utf-8')
    encrypted_pwd_str = bcrypt.hashpw(sha_pwd_bytes, bcrypt.gensalt()).decode('utf-8')
    try:
        m.User.objects.create(email=request.POST['email'], fullname=request.POST['fullname'], encrypted_pwd=encrypted_pwd_str)
        return True
    except django.db.utils.IntegrityError:
        messages.error(request, 'email address already in use!')
    except Exception as ex:
        print('{}: {}'.format(type(ex), ex))
        messages.error(request, 'internal server error: contact support!')
    return False

def login_user(request):
    if (not check_ajax_fields(request, ['email', 'sha_pwd'])):
        return False
    sha_pwd_bytes = request.POST['sha_pwd'].encode('utf-8')
    try:
        user = m.User.objects.get(email=request.POST['email'])
        encrypted_pwd_bytes = user.encrypted_pwd.encode('utf-8')
        if (bcrypt.checkpw(sha_pwd_bytes, encrypted_pwd_bytes)):
            request.session['user_id'] = user.id
            request.session['fullname'] = user.fullname
            return True
        messages.error(request, 'login failed!')
        return False
    except m.User.DoesNotExist:
        messages.error(request, 'email not registered!')
    except Exception as ex:
        print('{}: {}'.format(type(ex), ex))
        messages.error(request, 'internal server error: contact support!')
    return False

def data_ajax(request):
    if (request.method != 'POST'):
        return JsonResponse({ 'errors': [ request.method + ' not permitted!' ] }, status=400)
    user = get_logged_in_user(request)
    if (not user):
        return JsonResponse({ 'errors': [ 'Not authenticated!' ] }, status=400)
    if ('action' not in request.POST):
        return JsonResponse({ 'errors': [ 'Bad data_ajax request!' ] }, status=400)
    if (request.POST['action'] == 'read'):
        try:
            entries = m.Entry.objects.filter(user_id=user.id)
            entries_as_json = json.loads(serializers.serialize('json', entries))
            return JsonResponse({ 'entries': entries_as_json })
        except Exception as ex:
            return JsonResponse({ 'errors': [ ex ] }, status=400)
    if (request.POST['action'] == 'add'):
        if ('desc' not in request.POST or 'amount' not in request.POST):
            return JsonResponse({ 'errors': [ 'Bad data_ajax request!' ] }, status=400)
        try:
            entry = m.Entry.objects.create(desc=request.POST['desc'], amount=request.POST['amount'], user_id=user.id)
            return JsonResponse({ 'entry_id': entry.id })
        except Exception as ex:
            return JsonResponse({ 'errors': [ ex ] }, status=400)
    return JsonResponse({ 'errors': [ 'Bad data_ajax request!' ] }, status=400)



from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from AuthenticationSite import settings
#import Authentication
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from . tokens import generate_token
from django.core.mail import EmailMessage, send_mail
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode


# Create your views here.
def home(request) :
    return render(request, "Authentication/index.html") 

def signup(request) :
    if request.method== "POST":
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        password = request.POST['password']
        password2 = request.POST['password2']

        if User.objects.filter(username=username):
            messages.error(request, "Username already exists! Please try other username")
            return redirect('home')

        if User.objects.filter(email=email):
            messages.error(request, "Email already exists! Please try other email")
            return redirect('home')
        
        if len(username) > 10:
            messages.error(request, "Username must be less than 10 characters")
            return redirect('home')
        
        if password != password2 :
            messages.error(request, "Passwords didn't match")
            return redirect('home')
        
        if not username.isalnum():
            messages.error(request, "Username must be alphanumeric")
            return redirect('home')


        myUser = User.objects.create_user(username, email, password)
        myUser.first_name = fname
        myUser.last_name = lname

        myUser.is_active = False

        myUser.save()

        messages.success(request, "Your account has been successfully created. We have sen you a confirmation e-mail")
     
      #welcome email

        subject = "Welcome to Login"
        message = "Hello" + myUser.first_name + "! \n" + "Welcome to AZeotropy \n THank you for visiting. We have sent you a confirmation mail. Please confirm your e-mail address. Thanking You Team AZeotropy"
        from_email = settings.EMAIL_HOST_USER
        to_list = [myUser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)


    #EMail confirmation link

        current_site = get_current_site(request)
        email_subject = "Confirm your email @ AZeotropy"
        message2  = render_to_string('email_confirmation.html', {
            'name' : myUser.first_name,
            'domain' : current_site.domain,
            'uid' : urlsafe_base64_encode(force_bytes(myUser.pk)),
            'token' : generate_token.make_token(myUser),
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myUser.email],
        )
        email.fail_silently = True
        email.send()






        return redirect('signin')

    return render(request, "Authentication/signup.html")




def signin(request) :

    if request.method == 'POST' :
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(username=username, password=password) 

        if user is not None:
            login(request, user)
            fname = user.first_name
            return render(request, 'Authentication/index.html', {'fname' : fname})
        else:
            messages.error(request, "Bad Credentials")
            return redirect('home')
        

    return render(request, "Authentication/signin.html")

def signout(request) :
    logout(request)
    messages.success(request, "Logged out successfully")
    return redirect('home')


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myUser = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        myUser = None

    if myUser is not None and generate_token.check_token(myUser, token):
        myUser.is_active = True
        myUser.save()
        login(request, myUser)
        return redirect('home')
    
    else:
        return render(request, 'activationfailed.html')




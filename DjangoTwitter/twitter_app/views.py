from django.template import RequestContext
from django.shortcuts import render_to_response
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from twitter_app.forms import AuthenticateForm, UserForm, TwitterForm
from twitter_app.models import Tweet

def index(request, auth_form=None, user_form=None):
    # User is logged in
    if request.user.is_authenticated():
        twitter_form = TwitterForm()
        user = request.user
        twitter_self = Tweet.objects.filter(user=user.id)
        twitter_buddies = Tweet.objects.filter(user__userprofile__in=user.profile.follows.all)
        tweets = twitter_self | twitter_buddies

        return render(request,
                      'buddies.html',
                      {'Tweet_form': twitter_form, 'user': user,
                       'tweets': tweets,
                       'next_url': '/', })
    else:
        # User is not logged in
        auth_form = auth_form or AuthenticateForm()
        user_form = user_form or UserForm()

        return render(request,
                      'index.html',
                      {'auth_form': auth_form, 'user_form': user_form, })


def user_login(request):
    # Like before, obtain the context for the user's request.
    context = RequestContext(request)

    # if the request is a HTTP POST, try to pull out the relevent information.
    if request.method == 'POST':
        # Gather the username and password provided by the user.
        # This information is obtained from the login form.
        username = request.POST['username']
        password = request.POST['password']

        # Use Django's machinery to attempt to see if the username/password
        # combination is valid - a User object is returned if it is.
        user = authenticate(username=username, password=password)

        # If we have a User object, the details are correct.
        # If None (Python's way of representing the absence of a value), no user
        # with matching credentials was found.
        if user:
            # Is the account active? It could have been disabled.
            if user.is_active:
                # If the account is valid and active, we can log the user in.
                # We'll send the user back to the homepage.
                login(request, user)
                return HttpResponseRedirect('/twitter_app/')
            else:
                # An inactive account was used - no logging in!
                return HttpResponse("Your twitter account is disabled.")
        else:
            # Bad login details were provided. So we can't log the user in.
            print "Invalid login details: {0}, {1}".format(username, password)
            context_dict = {'bad_details': "Invalid login details supplied."}
            return render_to_response('twitter_app/login.html', context_dict, context)


    # The request is not a HTTP POST, so display the login form.
    # This scenario would most likely be a HTTP GET.
    else:
        # No context variables to pass to the template system, hence the
        # blank dictionary object...
        return render_to_response('twitter_app/login.html', {}, context)


def user_logout(request):
    # Since we know the user is logged in, we can now just log them out.
    logout(request)

    # Take the user back to the homepage.
    return HttpResponseRedirect('/twitter_app/')

def register(request):
    ## Cookie Test
    #if request.session.test_cookie_worked():
    #    print ">>>>> TEST COOKIE WORKED!"
    #    request.session.delete_test_cookie()
        
    # Like before, get the request's context.
    context = RequestContext(request)

    # A boolean value for telling the template whether the registration was successful
    # Set to False initially. Code changes value to True when registration succeeds.
    registered = False

    # If it's a HTTP POST, we're interested in processing form data.
    if request.method == 'POST':
        # Attempt to grab information from the raw form information.
        # Note that we make use of both UserForm and UserProfileForm.
        user_form = UserForm(data=request.POST)
        # profile_form = UserProfileForm(data=request.POST)

        # if the two forms are valid...
        if user_form.is_valid():
            # Save the user's form data to the database.
            user = user_form.save()

            # Now we hash the password with the set_password method.
            # Once hased, we can update the user object.
            user.set_password(user.password)
            user.save()

            # # Now sort out the UserProfile instance.
            # # Since we need to set the user attribute ourselves, we set commit=False.
            # # This delays saving the model until we're ready to avoid integrity problems.
            # profile = profile_form.save(commit=False)
            # profile.user = user

            # # Did the user provide a profile picture?
            # # If so, we need to get it from the input form and put it in the UserProfile model.
            # if 'picture' in request.FILES:
            #     profile.picture = request.FILES['picture']

            # # Now we save the UserProfile model instance.
            # profile.save()

            # Update our variable to tell the template registration was successful.
            registered = True

        # Invalid for or forms - mistakes of somthing else?
        # Print problems to the terminal.
        # They'll also be shown to the user.
        else:
            print user_form.errors,

    # Not a HTTP POST, so we render our form using two ModelForm instances.
    # These forms will be blank, ready for user input.
    else:
        user_form = UserForm(data=request.POST)
        # profile_form = UserProfileForm(data=request.POST)

    # Render the template depending on the context.
    return render_to_response(
        'twitter_app/register.html',
        {'user_form': user_form, 'registered':registered},
        context)

@login_required
def submit(request):
    if request.method == "POST":
        twitter_form = TwitterForm(data=request.POST)
        next_url = request.POST.get("next_url", "/")
        if twitter_form.is_valid():
            tweet = twitter_form.save(commit=False)
            tweet.user = request.user
            tweet.save()
            return redirect(next_url)
        else:
            return public(request, twitter_form)
    return redirect('/')
 

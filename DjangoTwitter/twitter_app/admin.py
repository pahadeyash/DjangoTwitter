from django.contrib import admin
from twitter_app.models import Tweet, UserProfile

admin.site.register(Tweet)
admin.site.register(UserProfile)
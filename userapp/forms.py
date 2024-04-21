from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
from .models import User
import fingerprint_pro_server_api_sdk
from fingerprint_pro_server_api_sdk import EventResponse
from fingerprint_pro_server_api_sdk.rest import ApiException, KnownApiException
import time

min_confidence = 0.5
max_request_lifespan = 60 * 5 # 5 minutes

configuration = fingerprint_pro_server_api_sdk.Configuration(api_key="<YOUR_SERVER_API_KEY>")
api_instance = fingerprint_pro_server_api_sdk.FingerprintApi(configuration)

class SignupForm(UserCreationForm):
    email = forms.EmailField(max_length=200, help_text='Required')
    fingerprint = forms.CharField(widget=forms.HiddenInput(), required=False)
    requestId = forms.CharField(widget=forms.HiddenInput(), required=False)

    class Meta:
        model = User
        fields = ['username', 'email', 'requestId', 'fingerprint', 'password1', 'password2']

    def clean_fingerprint(self):
        fingerprint = self.cleaned_data.get('fingerprint')
        requestId = self.cleaned_data.get('requestId')

        if requestId:
            try:
                # Get the fingerprint from the requestId
                event = api_instance.get_event(requestId)

                event_json = event.to_dict()
                identification = event_json['products']['identification']['data']
                
                server_visitor_id = identification['visitor_id']
                identification_timestamp = identification['timestamp'] / 1000
                confidence = identification['confidence']['score']
                
                # Check if the fingerprint is valid
                time_now = int(time.time())

                if time_now - identification_timestamp > max_request_lifespan:
                    raise ValidationError('Fingerprint request expired.')

                if server_visitor_id != fingerprint:
                    raise ValidationError('Fingerprint forgery detected.')
                
                if confidence < min_confidence:
                    raise ValidationError('Fingerprint confidence too low.')
            except ApiException as e:
                print("Exception when calling FingerprintApi->get_event: %s\n" % e)
                raise ValidationError('Invalid fingerprint.')
        
        if fingerprint:
            # Check if a user with the same fingerprint already exists
            # This is only for demonstration purposes, in a real-world scenario you should use a threshold to determine if the fingerprint was used more than n times in the last t minutes. 
            existing_user = User.objects.filter(fingerprint=fingerprint).exclude(pk=self.instance.pk).first()
            if existing_user:
                raise ValidationError('Another user with the same fingerprint already exists.')   
        
        return fingerprint

    def save(self, commit=True):
        user = super(SignupForm, self).save(commit=False)
        user.fingerprint = self.cleaned_data['fingerprint']
        if commit:
            user.save()
        return user


class LoginForm(forms.Form):
    username = forms.CharField(max_length=200)
    password = forms.CharField(widget=forms.PasswordInput())
from django import forms


from authentic2.compat import get_user_model


class UserProfileForm(forms.ModelForm):
    error_css_class = 'form-field-error'
    required_css_class = 'form-field-required'

    def __init__(self, user=None, *args, **kwargs):
        self.user = user
        super(UserProfileForm, self).__init__(**kwargs)
        for field in get_user_model().REQUIRED_FIELDS:
            self.fields[field].required = True

    def save(self, commit=True):
        instance = super(UserProfileForm, self).save(commit=False)
        instance.user = self.user
        if commit:
            instance.save()
        return instance

    class Meta:
        model = get_user_model()
        fields = [ field_name
                for field_name in get_user_model().USER_PROFILE
                if field_name in get_user_model()._meta.get_all_field_names()
                    and not field_name == get_user_model().USERNAME_FIELD ]

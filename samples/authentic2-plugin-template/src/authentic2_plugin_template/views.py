from django.shortcuts import render


from . import decorators

__ALL_ = [ 'sso' ]

@decorators.plugin_enabled
def index(request):
    return render(request, 'authentic2_plugin_template/index.html')

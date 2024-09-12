from rest_framework import renderers
import json

class UserRenderer(renderers.JSONRenderer):
    charset = 'utf-8'

    def render(self, data, accepted_media_type=None, renderer_context=None):
        response = ''
        if 'errors' in data:
            response = json.dumps({'errors': data['errors']})
        elif 'ErrorDetail' in str(data):
            response = json.dumps({'errors': {'message': str(data)}})
        else:
            response = json.dumps({'data': data})
        
        return response
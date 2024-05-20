from rest_framework.exceptions import APIException

class ValidationError(APIException):
    status_code = 400
    default_detail = 'Invalid input.'
    default_code = 'invalid'
    
    def __init__(self, detail=None, code=None):
        if detail is not None:
            self.detail = {'error': detail}
        if code is not None:
            self.default_code = code
        super().__init__(detail, code)
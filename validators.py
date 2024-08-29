from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import MinimumLengthValidator

class CustomPasswordValidator(MinimumLengthValidator):
    def validate(self, password, user=None):
        super().validate(password, user)
        if not any(char.isdigit() for char in password):
            raise ValidationError("La contraseña debe contener al menos un carácter numérico.")
        if not any(char in "!@#$%^&*()-_+=" for char in password):
            raise ValidationError("La contraseña debe contener al menos un carácter especial.")

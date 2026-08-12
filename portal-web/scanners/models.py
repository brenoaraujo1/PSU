from django.db import models

class Scan(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pendente'),
        ('RUNNING', 'Em Execução'),
        ('COMPLETED', 'Concluído'),
        ('FAILED', 'Falhou'),
    ]

    target = models.CharField(max_length=255, help_text="IP ou Domínio alvo")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    created_at = models.DateTimeField(auto_now_add=True)
    output = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Scan: {self.target} - Status: {self.status}"
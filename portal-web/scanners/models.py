from django.db import models


class Scan(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pendente'),
        ('RUNNING', 'Em Execução'),
        ('COMPLETED', 'Concluído'),
        ('FAILED', 'Falhou'),
    ]

    SCAN_TYPE_CHOICES = [
        ('nmap', 'Nmap'),
        ('gobuster', 'Gobuster'),
        ('nuclei', 'Nuclei'),
    ]

    target = models.CharField(max_length=255, help_text="IP, Domínio ou URL alvo")
    scan_type = models.CharField(
        max_length=20, choices=SCAN_TYPE_CHOICES, default='nmap',
        help_text="Ferramenta de varredura a ser executada"
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    task_id = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(blank=True, null=True)
    output = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Scan #{self.id} [{self.scan_type}]: {self.target} - {self.status}"

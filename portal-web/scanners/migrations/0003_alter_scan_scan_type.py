from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanners', '0002_scan_fields'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scan',
            name='scan_type',
            field=models.CharField(
                choices=[
                    ('nmap', 'Nmap'),
                    ('gobuster', 'Gobuster'),
                    ('nuclei', 'Nuclei'),
                    ('masscan', 'Masscan'),
                ],
                default='nmap',
                help_text='Ferramenta de varredura a ser executada',
                max_length=20,
            ),
        ),
    ]

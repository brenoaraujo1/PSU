from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanners', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='scan_type',
            field=models.CharField(
                choices=[('nmap', 'Nmap'), ('gobuster', 'Gobuster'), ('nuclei', 'Nuclei')],
                default='nmap',
                help_text='Ferramenta de varredura a ser executada',
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name='scan',
            name='task_id',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='scan',
            name='finished_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='scan',
            name='target',
            field=models.CharField(help_text='IP, Domínio ou URL alvo', max_length=255),
        ),
        migrations.AlterModelOptions(
            name='scan',
            options={'ordering': ['-created_at']},
        ),
    ]

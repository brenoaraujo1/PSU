from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from .models import Scan
from .services import UnknownScanTypeError, create_and_dispatch
from .validators import InvalidTargetError, validate_ip_or_cidr, validate_target

NUCLEI_DELAY = 'scanners.tasks.run_nuclei_scan.delay'
MASSCAN_DELAY = 'scanners.tasks.run_masscan_scan.delay'


class ValidateTargetTests(TestCase):
    def test_aceita_ip_e_dominio(self):
        self.assertEqual(validate_target('192.168.1.10', allow_url=False), '192.168.1.10')
        self.assertEqual(validate_target('exemplo.com.br', allow_url=False), 'exemplo.com.br')

    def test_aceita_host_com_porta(self):
        self.assertEqual(validate_target('exemplo.com:8080'), 'exemplo.com:8080')

    def test_aceita_url_http_e_https(self):
        self.assertEqual(validate_target('https://exemplo.com/app'), 'https://exemplo.com/app')

    def test_rejeita_injecao_de_flag(self):
        with self.assertRaises(InvalidTargetError):
            validate_target('--script=http-brute')

    def test_rejeita_espacos_e_caracteres_de_shell(self):
        for alvo in ['exemplo.com; rm -rf /', 'a b.com', 'exemplo.com|id', '$(id)']:
            with self.subTest(alvo=alvo):
                with self.assertRaises(InvalidTargetError):
                    validate_target(alvo)

    def test_rejeita_url_para_nmap(self):
        with self.assertRaises(InvalidTargetError):
            validate_target('http://exemplo.com', allow_url=False)

    def test_rejeita_esquema_nao_http(self):
        with self.assertRaises(InvalidTargetError):
            validate_target('file:///etc/passwd')

    def test_rejeita_vazio_e_porta_invalida(self):
        with self.assertRaises(InvalidTargetError):
            validate_target('   ')
        with self.assertRaises(InvalidTargetError):
            validate_target('exemplo.com:99999')


class ValidateIpOrCidrTests(TestCase):
    def test_aceita_ip_e_cidr(self):
        self.assertEqual(validate_ip_or_cidr('10.0.0.1'), '10.0.0.1')
        self.assertEqual(validate_ip_or_cidr('10.0.0.0/24'), '10.0.0.0/24')

    def test_rejeita_hostname_url_e_injecao(self):
        for alvo in ['exemplo.com', 'http://10.0.0.1', '-oX /tmp/x', '10.0.0.0/99']:
            with self.subTest(alvo=alvo):
                with self.assertRaises(InvalidTargetError):
                    validate_ip_or_cidr(alvo)


class DispatchServiceTests(TestCase):
    def test_tipo_desconhecido_levanta_erro(self):
        with self.assertRaises(UnknownScanTypeError):
            create_and_dispatch('sqlmap', 'exemplo.com')
        self.assertEqual(Scan.objects.count(), 0)

    @mock.patch(NUCLEI_DELAY)
    def test_cria_registro_e_enfileira(self, delay):
        delay.return_value = mock.Mock(id='t-1')
        scan, task = create_and_dispatch('nuclei', 'https://exemplo.com')
        delay.assert_called_once_with(scan.id)
        scan.refresh_from_db()
        self.assertEqual(scan.task_id, 't-1')
        self.assertEqual(task.id, 't-1')



class TriggerScanViewTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user('tester', password='senha-forte-123')
        self.client_api = APIClient()
        self.client_api.force_authenticate(user=self.user)
        self.url = '/api/scan/start/'

    def test_exige_autenticacao(self):
        resp = APIClient().post(self.url, {'scan_type': 'nmap', 'target': 'exemplo.com'}, format='json')
        self.assertIn(resp.status_code, (401, 403))

    def test_rejeita_scan_type_invalido(self):
        resp = self.client_api.post(self.url, {'scan_type': 'sqlmap', 'target': 'exemplo.com'}, format='json')
        self.assertEqual(resp.status_code, 400)

    def test_rejeita_alvo_malicioso_sem_criar_registro(self):
        resp = self.client_api.post(self.url, {'scan_type': 'nmap', 'target': '-oX /tmp/x'}, format='json')
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(Scan.objects.count(), 0)

    @mock.patch(NUCLEI_DELAY)
    def test_dispara_task_com_scan_id(self, delay):
        delay.return_value = mock.Mock(id='abc-123')
        resp = self.client_api.post(
            self.url, {'scan_type': 'nuclei', 'target': 'https://exemplo.com'}, format='json'
        )
        self.assertEqual(resp.status_code, 202)
        scan = Scan.objects.get()
        delay.assert_called_once_with(scan.id)
        self.assertEqual(resp.data['scan_id'], scan.id)
        self.assertEqual(resp.data['task_id'], 'abc-123')
        self.assertEqual(resp.data['status'], 'scan_initiated')

    @mock.patch(MASSCAN_DELAY)
    def test_masscan_rejeita_hostname(self, delay):
        resp = self.client_api.post(
            self.url, {'scan_type': 'masscan', 'target': 'exemplo.com'}, format='json'
        )
        self.assertEqual(resp.status_code, 400)
        delay.assert_not_called()

    @mock.patch(MASSCAN_DELAY)
    def test_masscan_aceita_cidr(self, delay):
        delay.return_value = mock.Mock(id='m-1')
        resp = self.client_api.post(
            self.url, {'scan_type': 'masscan', 'target': '10.0.0.0/24'}, format='json'
        )
        self.assertEqual(resp.status_code, 202)

    def test_consulta_status_do_scan(self):
        scan = Scan.objects.create(target='exemplo.com', scan_type='nmap', status='COMPLETED', output='ok')
        resp = self.client_api.get(f'/api/scan/{scan.id}/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['status'], 'COMPLETED')
        self.assertEqual(resp.data['output'], 'ok')

    def test_consulta_scan_inexistente(self):
        resp = self.client_api.get('/api/scan/999999/')
        self.assertEqual(resp.status_code, 404)


class WebPanelTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user('painel', password='senha-forte-123')
        self.client.force_login(self.user)

    def test_painel_exige_login(self):
        self.client.logout()
        resp = self.client.get(reverse('dashboard'))
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse('login'), resp.url)

    def test_painel_carrega_para_usuario_logado(self):
        resp = self.client.get(reverse('dashboard'))
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, 'scanners/dashboard.html')
        self.assertContains(resp, 'Iniciar nova varredura')

    @mock.patch(NUCLEI_DELAY)
    def test_post_cria_scan_e_redireciona_para_detalhe(self, delay):
        delay.return_value = mock.Mock(id='w-1')
        resp = self.client.post(reverse('dashboard'), {'scan_type': 'nuclei', 'target': 'https://exemplo.com'})
        scan = Scan.objects.get()
        self.assertRedirects(resp, reverse('scan_detail', args=[scan.id]))
        delay.assert_called_once_with(scan.id)

    def test_post_alvo_invalido_mostra_erro_sem_criar_scan(self):
        resp = self.client.post(reverse('dashboard'), {'scan_type': 'nmap', 'target': '-oX /tmp/x'}, follow=True)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Alvo inválido')
        self.assertEqual(Scan.objects.count(), 0)

    def test_detalhe_mostra_saida(self):
        scan = Scan.objects.create(target='exemplo.com', scan_type='nmap', status='COMPLETED', output='PORTA 80 open')
        resp = self.client.get(reverse('scan_detail', args=[scan.id]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'PORTA 80 open')

    def test_detalhe_inexistente_retorna_404(self):
        resp = self.client.get(reverse('scan_detail', args=[999999]))
        self.assertEqual(resp.status_code, 404)

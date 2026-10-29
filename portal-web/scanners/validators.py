"""
Validação de alvos de varredura.

Objetivo de segurança: impedir injeção de argumentos de linha de comando
(ex.: um alvo começando com '-' seria interpretado como opção pelo Nmap/Nuclei)
e restringir a entrada a hostnames, IPs ou URLs válidos.
"""
import ipaddress
import re
from urllib.parse import urlparse

# Hostname RFC 1123 (rótulos separados por ponto, sem caracteres de shell).
_HOSTNAME_RE = re.compile(
    r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)'
    r'(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$'
)


class InvalidTargetError(ValueError):
    """Alvo inválido ou potencialmente malicioso."""


def _is_valid_host(host: str) -> bool:
    if not host:
        return False
    # Aceita IPv4/IPv6 literais.
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(host))


def validate_ip_or_cidr(target: str) -> str:
    """
    Valida alvo para ferramentas que aceitam apenas endereços IP ou faixas CIDR
    (ex.: Masscan). Nomes de host e URLs são rejeitados.
    """
    target = validate_target(target, allow_url=False)
    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError:
        raise InvalidTargetError(
            f"Alvo deve ser um IP ou faixa CIDR (ex.: 10.0.0.1 ou 10.0.0.0/24): '{target}'."
        )
    return target


def validate_target(target: str, allow_url: bool = True) -> str:
    """
    Valida e normaliza o alvo.

    - Rejeita valores vazios, com espaços ou iniciando com '-' (injeção de flag).
    - Para nmap/gobuster-host aceita IP ou hostname.
    - Para alvos web (nuclei/gobuster) aceita também URLs http/https.

    Retorna o alvo normalizado (sem espaços nas bordas) ou levanta
    InvalidTargetError.
    """
    if not isinstance(target, str):
        raise InvalidTargetError("O alvo deve ser uma string.")

    target = target.strip()

    if not target:
        raise InvalidTargetError("O alvo não pode ser vazio.")
    if target.startswith('-'):
        raise InvalidTargetError("O alvo não pode começar com '-'.")
    if any(c.isspace() for c in target):
        raise InvalidTargetError("O alvo não pode conter espaços.")

    # URL completa (http/https).
    if '://' in target:
        if not allow_url:
            raise InvalidTargetError("URLs não são permitidas para este scan.")
        parsed = urlparse(target)
        if parsed.scheme not in ('http', 'https'):
            raise InvalidTargetError("Apenas esquemas http/https são aceitos.")
        host = parsed.hostname or ''
        if not _is_valid_host(host):
            raise InvalidTargetError(f"Host inválido na URL: '{host}'.")
        return target

    # Host simples (IP ou domínio), opcionalmente com :porta.
    host = target
    if target.count(':') == 1 and ']' not in target:  # host:porta (não IPv6)
        host, _, port = target.partition(':')
        if not port.isdigit() or not (0 < int(port) <= 65535):
            raise InvalidTargetError(f"Porta inválida: '{port}'.")

    if not _is_valid_host(host):
        raise InvalidTargetError(f"Alvo inválido: '{target}'.")

    return target

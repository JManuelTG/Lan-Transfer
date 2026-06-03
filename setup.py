from setuptools import setup

setup(
    name='lan-transfer',
    version='1.0.0',
    description='Herramienta ultrarrápida P2P para transferir archivos en LAN.',
    py_modules=['lan'],
    install_requires=[
        'tqdm>=4.66.0',
        'requests>=2.31.0',
        'rich>=13.0.0'
    ],
    entry_points={
        'console_scripts': [
            # Esto crea el comando global "lan-transfer" que apunta a la función "main" en lan.py
            'lan-transfer=lan:main',
        ],
    },
)

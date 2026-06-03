.PHONY: install uninstall clean

install:
	@echo "Instalando LAN Transfer..."
	pip install .
	@echo "=========================================================="
	@echo "¡Instalación completada!"
	@echo "El comando 'lan-transfer' ha sido agregado a tu PATH."
	@echo "Pruébalo abriendo cualquier consola y escribiendo: lan-transfer --help"
	@echo "=========================================================="

uninstall:
	@echo "Desinstalando LAN Transfer..."
	pip uninstall -y lan-transfer
	@echo "Desinstalación completada."

clean:
	@echo "Limpiando basura de empaquetado..."
	-rmdir /s /q build
	-rmdir /s /q lan_transfer.egg-info
	-rmdir /s /q __pycache__

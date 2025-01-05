import angr
from angr.knowledge_plugins.patches import PatchManager

sources = []


def patch_nop(addr, bytes, pm):
    patch_data = b'\x90' * bytes
    pm.add_patch(addr, patch_data)


def bin_save(file_name, pm):
    patched_data = pm.apply_patches_to_binary()
    with open(file_name, "wb") as patched_file:
        patched_file.write(patched_data)


# Загрузите бинарный файл
project = angr.Project("test1.exe", load_options={'auto_load_libs': False})

# Создайте объект PatchManager
pm = project.kb.patches  # Получение PatchManager из проекта

patch_nop(0x14000108e, 6, pm)

bin_save("example.exe", pm)

print("Патчинг завершен. Новый файл сохранен как output.exe.")

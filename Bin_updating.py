import angr
from angr.knowledge_plugins.patches import PatchManager

# Загрузите бинарный файл
project = angr.Project("test1.exe", load_options={'auto_load_libs': False})

# Создайте объект PatchManager
pm = project.kb.patches  # Получение PatchManager из проекта

# Адрес для патча (замените на свой адрес)
target_address = 0x14000108e

# Данные для патча (NOP-инструкции)
patch_data = b'\x90\x90\x90\x90\x90\x90'

# Добавьте патч
pm.add_patch(target_address, patch_data)

# Примените патчи и сохраните результат
patched_data = pm.apply_patches_to_binary()  # Создание модифицированного бинарного файла
with open("output.exe", "wb") as patched_file:
    patched_file.write(patched_data)

print("Патчинг завершен. Новый файл сохранен как output.exe.")

// ==== CHAINLOAD: запуск стороннего EFI-образа (bootmgfw/grub/...) ====
//
// Пейлоад type="efi" из boot_cfg.xml загружается СТАНДАРТНЫМ путём
// прошивки: LoadImage по ПОЛНОМУ device path (том нашей ESP + узел
// MEDIA_FILE_PATH) + StartImage. Важно именно LoadImage по device path,
// а не из буфера: загрузчик ребёнка (BCD у Windows, prefix у GRUB)
// находит свои данные по СОБСТВЕННОМУ device path — загрузка из буфера
// оставила бы его без пути.
//
// Device path тома берём как в get_image_file_system: LoadedImage.device
// → протокол DevicePath → locate_device_path(SimpleFileSystem) укорачивает
// путь до границы FS (та же последовательность, что uefi-rs применяет
// для поиска ESP). Дальше: байты тома (без концевого END-узла) + узел
// файла (UCS-2 путь) + END → DevicePath::try_from(байты).
//
// StartImage возвращается, только если образ сам вышел (exit) — для
// загрузчиков это НЕ норма; заглушка логирует и возвращается в меню
// (повторный chainload — только явным выбором, без обратного отсчёта:
// неудачный default не должен пинг-понгнуть машину).

use alloc::string::String;
use alloc::vec::Vec;

use uefi::boot::{self, LoadImageSource, image_handle, open_protocol_exclusive};
use uefi::proto::device_path::{DevicePath, LoadedImageDevicePath};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{Error, Status};

// ───────────────────── Device path: узлы ─────────────────────

/// Тип/подтипы узлов, которые мы строим (UEFI spec, Device Paths).
const DP_MEDIA: u8 = 0x04;
const DP_MEDIA_FILE: u8 = 0x04;
const DP_END_ENTIRE: u8 = 0x7F;

/// Узел MEDIA_FILE_PATH: `[type][sub][len:u16] + UCS-2 путь + NUL`.
fn file_path_node(path16: &[u16]) -> Vec<u8> {
    let len = 4 + (path16.len() + 1) * 2; // заголовок + строка + L'\0'
    let mut node = Vec::with_capacity(len);
    node.push(DP_MEDIA);
    node.push(DP_MEDIA_FILE);
    node.extend_from_slice(&(len as u16).to_le_bytes());
    for &u in path16 {
        node.extend_from_slice(&u.to_le_bytes());
    }
    node.extend_from_slice(&0u16.to_le_bytes());
    node
}

/// END-узел: `[0x7F][0xFF][len=4]`.
fn end_node() -> [u8; 4] {
    [DP_END_ENTIRE, 0xFF, 0x04, 0x00]
}

/// Полный device path (байты): путь тома без END + файл + END.
///
/// Путь тома приходит как `&DevicePath` (as_bytes уже включает END);
/// END-узлы с хвоста снимаются проходом вперёд по длинам узлов.
fn build_full_path(volume: &DevicePath, path16: &[u16]) -> Option<Vec<u8>> {
    let src = volume.as_bytes();
    let mut node_off = 0usize;
    let mut body_end = 0usize; // конец последнего не-END узла
    while node_off + 4 <= src.len() {
        let len = u16::from_le_bytes([src[node_off + 2], src[node_off + 3]]) as usize;
        if len < 4 || node_off + len > src.len() {
            return None; // битый путь тома — не гадаем
        }
        if src[node_off] != DP_END_ENTIRE {
            body_end = node_off + len;
        }
        node_off += len;
    }
    let mut out = Vec::with_capacity(body_end + 4 + (path16.len() + 1) * 2 + 4);
    out.extend_from_slice(&src[..body_end]);
    out.extend_from_slice(&file_path_node(path16));
    out.extend_from_slice(&end_node());
    Some(out)
}

// ───────────────────── Запуск ─────────────────────

/// Загрузить и стартовать EFI-образ по пути от корня тома.
///
/// Возврат Ok(()) = образ вышел сам (exit): заглушка возвращается в
/// меню. Err = LoadImage/StartImage отказали (нет файла / не PE / сбой).
pub fn run(path: &str) -> Result<(), Error> {
    // 1. Полный device path САМОЙ заглушки: LoadedImageDevicePath на
    //    нашем хендле = [узлы тома..., FILE(\EFI\BOOT\BOOTX64.EFI), END].
    //
    //    ВАЖНО: locate_device_path УКОРАЧИВАЕТ входной путь до
    //    НЕпокрытого хвоста (у нас хвост = узел файла) и возвращает
    //    хендл, чей префикс совпал, — хендл SimpleFileSystem тома.
    //    Путь ТОМА тогда — DevicePath-протокол этого хендла. Повторный
    //    exclusive-open ДРУГОГО протокола не конфликтует (а вот DevicePath
    //    на одном хендле дважды firmware запрещает — ACCESS_DENIED).
    let own = open_protocol_exclusive::<LoadedImageDevicePath>(image_handle())?;
    let mut probe: &DevicePath = &own;
    let fs_handle = boot::locate_device_path::<SimpleFileSystem>(&mut probe)?;
    let volume = open_protocol_exclusive::<DevicePath>(fs_handle)?;

    // 2. Путь файла: UCS-2 от КОРНЯ тома (ведущий '\' не обязателен).
    let normalized: String = if path.starts_with('\\') {
        String::from(path)
    } else {
        alloc::format!("\\{}", path)
    };
    let path16: Vec<u16> = normalized.encode_utf16().collect();

    // 3. Полный device path: том + файл.
    let bytes = build_full_path(&volume, &path16)
        .ok_or_else(|| Error::new(Status::INVALID_PARAMETER, ()))?;
    let full: &DevicePath = <&DevicePath>::try_from(bytes.as_slice())
        .map_err(|_| Error::new(Status::INVALID_PARAMETER, ()))?;

    // Полный путь собран в СОБСТВЕННЫЕ байты — освобождаем
    // EXCLUSIVE-открытия ДО загрузки/запуска: ребёнок сам откроет
    // DevicePath/SFS этого тома (get_image_file_system), а атрибут
    // EXCLUSIVE не терпит параллельных открытий (ACCESS_DENIED).
    core::mem::drop(volume);
    core::mem::drop(own);

    // 4. Загрузка и запуск. Watchdog уже выключен main'ом (дети вроде
    //    Windows ведут свой таймер сами).
    let child = boot::load_image(
        image_handle(),
        LoadImageSource::FromDevicePath {
            device_path: full,
            boot_policy: uefi::proto::BootPolicy::ExactMatch,
        },
    )?;
    boot::start_image(child)
}

# powershell_add_users
batch adding users to MS AD

## RUS
Скрипт Add-UserAD.ps1 предназначен для создания пользователей домена на основании исходных данных.
Скрипт запускается ярлыком ADD-USERS.lnk

Файл настроек *.conf должен содержать обязательные параметры:
| **Параметр** | **Описание**  |
|----------------------------|------------------------------------------------------------|
| PATTERN_SEARCH |  - Регулярное выражение с именованными группами для трансляции их карту полей записи. |
| POSITION_FILTER_LIST |  Список разделенных "," фильтров отбора полученных записей по значению заданного поля . Содержит название поля (FILTER) соответствующее одной из групп отбора в верхнем регистре. |
| POSITION_FILTER_LIST |  Список разделенных "," фильтров отбора полученных записей по значению заданного поля . Содержит название поля (FILTER) соответствующее одной из групп отбора в верхнем регистре. |
| FILTER_LIST_ENABLE |  Включение фильтрации (допустимые значения: true - включен и false - выключен). |
| DOMAIN | Название домена. |
| OU_PATH | Organization unit куда будут добавляться пользователи. |
| COMPANY | Наименование компании (будет проставлено у всех добавляемых сотрудников). |
| PASS_NUMBER_GROUP	| Количество групп в генерируемом пароле. |
| PASS_GROUP_CHAR_LENGHT	| Количество групп в генерируемом пароле. |
| PASS_GROUP_CHAR_SEPARATOR	| Разделитель групп в генерируемом пароле. |
| DEFAULT_GROUP	| Список групп по умолчанию для всех пользователей. |
| GROUPS_PATTERN_DIVISION_1	| Регулярное выражение на основании которого производится сопоставление значения поля на основании которого пользователю будут назначены группы. Содержит название поля (PATTERN) соответствующее одной из групп отбора в верхнем регистре. Номер группы для добавления (групп может быть от 1 до 9). |
| GROUPS_1	| Список групп, разделенных "," в которые необходимо добавить сотрудника в соответствии с шаблоном GROUPS_PATTERN_DIVISION_1. Содержит номер группы для добавления (групп может быть от 1 до 9). |

По умолчанию регулярное список для фильтрации содержит должности которым разрешен доступ к ИС.

По умолчанию регулярное выражение для отбора входных данных (выгрузка 1С-ЗуП):

| **Реквизит 1С** | **Поле**  |
|----------------------------|------------------------------------------------------------|
| Сотрудник |  fio  |
| Комментарий |  komment (опционально может содержался в поле исходных данных "Сотрудник")|
| Комментарий |  birthdate  |
| Дата рождения |  registration (может быть пустым)|
| Адрес места проживания |  id_serial (может быть пустым)|
| Серия(паспорт)	 |  id_number (может быть пустым)|
| Дата(паспорт) выдачи |  date_of_issue (может быть пустым)|
| Кем выдано(паспорт) |  owner_id (может быть пустым)|
| Код подразделения(паспорт) |  owner_id_number (может быть пустым)|
| Должность по штатному расписанию |  position |
| Подразделение |  division (содержится в поле исходных данных "Должность по штатному расписанию")|
| Пол |  gender (может быть пустым)|



CREATE TABLE owners (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), -- Уникальный идентификатор владельца (UUID).
                        name VARCHAR(255) NOT NULL, -- Имя владельца (например, название киностудии или имя режиссёра).
                        email VARCHAR(255) UNIQUE, -- Контактный email для связи с владельцем.
                        password_hash TEXT NOT NULL,
                        phone VARCHAR(20), -- Телефонный номер для связи.
                        kind VARCHAR(50) NOT NULL, -- Вид владельца: 'individual' (физическое лицо) или 'organization' (организация).
                        description TEXT, -- Описание владельца (например, биография режиссёра или информация о киностудии).
                        is_active BOOLEAN DEFAULT TRUE, -- Флаг активности владельца (можно деактивировать при необходимости).
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), -- Дата и время создания записи.
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() -- Дата последнего изменения данных.
);
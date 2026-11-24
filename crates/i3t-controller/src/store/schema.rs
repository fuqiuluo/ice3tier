//! 表结构和它的演进。
//!
//! 库里的 `schema_version` 表只有一行，记着已经执行到第几条迁移。打开时把还没执行的依次执行，每条在自己的事务里。
//! 所以改表结构的办法只有一个：在 [`MIGRATIONS`] 末尾加一条，已经发布过的不能改。
//!
//! 每条迁移是 `migrations/` 下面的一个 SQL 文件，文件名是四位的序号加一段英文说明（`0001_initial.sql`），
//! 编译时通过 `include_str!` 嵌入。文件顶部的 `--` 注释说明该迁移的动机。新增迁移时按连续序号添加文件，
//! 并将其追加至 [`MIGRATIONS`] 末尾；单元测试会校验文件列表与数组一致。
//!
//! 列的写法：整数一律 `BIGINT`（编号、计数、Unix 秒的时间，虚拟 IP 也存成整数），开关是 `BOOLEAN`，
//! 枚举和结构体按它们的 JSON 形式存在 `JSONB` 列里，地址存文本，公钥和哈希存 `BYTEA`。

pub(super) const MIGRATIONS: &[&str] = &[
    include_str!("migrations/0001_initial.sql"),
    include_str!("migrations/0002_stats_by_step_at.sql"),
    include_str!("migrations/0003_mcp_tokens.sql"),
];

#[cfg(test)]
mod tests {
    use super::MIGRATIONS;
    use crate::store::Store;

    #[test]
    fn every_file_in_the_migrations_directory_is_applied_in_name_order_without_gaps() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/store/migrations");
        let mut names: Vec<String> =
            std::fs::read_dir(&dir).unwrap().map(|entry| entry.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        assert!(names.iter().all(|name| name.ends_with(".sql")), "目录里只放迁移：{names:?}");
        assert_eq!(names.len(), MIGRATIONS.len(), "每个文件都要在 MIGRATIONS 里，反过来也一样：{names:?}");
        for (index, name) in names.iter().enumerate() {
            let (number, description) = name.split_once('_').unwrap_or_else(|| panic!("{name} 要写成 序号_说明.sql"));
            assert_eq!(number.len(), 4, "{name} 的序号是四位数");
            assert_eq!(number.parse::<usize>().unwrap(), index + 1, "{name}：序号从 1 起，一个接一个，不能有空缺");
            assert!(description.len() > ".sql".len(), "{name} 要有一段说明");
            let content = std::fs::read_to_string(dir.join(name)).unwrap();
            assert_eq!(MIGRATIONS[index], content, "MIGRATIONS[{index}] 应该是 {name}");
        }
    }

    /// 整数列一律 `BIGINT`、JSON 一律 `JSONB`：读写的代码（`codec`）只认这两种，别的写法在用到那一列时才会出错。
    #[test]
    fn every_column_uses_one_of_the_types_the_codec_knows() {
        let store = Store::temporary();
        let odd: Vec<String> = store
            .query(
                "SELECT table_name || '.' || column_name || ' ' || data_type FROM information_schema.columns
                 WHERE table_schema = current_schema()
                   AND data_type NOT IN ('bigint', 'boolean', 'text', 'bytea', 'jsonb', 'double precision')
                 ORDER BY 1",
                &[],
                |row| row.try_get(0),
            )
            .unwrap();
        assert!(odd.is_empty(), "{odd:?}");
    }
}

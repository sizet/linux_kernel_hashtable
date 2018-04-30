// ©.
// https://github.com/sizet/lkm_hashtable

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/list.h>




#define FILE_NAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define DMSG(msg_fmt, msg_args...) \
    printk(KERN_INFO "%s(%04u): " msg_fmt "\n", FILE_NAME, __LINE__, ##msg_args)




// 要記錄的資料, 記錄每個產品的名稱和價格.
struct product_t
{
    // 雜湊節點.
    struct hlist_node hnode;
    // 產品名稱.
    char name[16];
    // 產品價格.
    unsigned int price;
};

// 雜湊表的大小.
#define MAX_HASH_TABLE_SIZE 5

// 雜湊表.
struct hlist_head product_hash_table[MAX_HASH_TABLE_SIZE];




#define PARAMETER_DATA_SPLIT_KEY  ' '
#define PARAMETER_VALUE_SPLIT_KEY '='

struct parameter_record_t
{
    char *data_name;
    char *data_value;
    unsigned int is_must;
};

enum PARA_RECORD_INDEX_LIST
{
    PR_OPERATE_INDEX = 0,
    PR_NAME_INDEX,
    PR_PRICE_INDEX,
};
struct parameter_record_t para_record_list[] =
{
    {"operate", NULL, 1},
    {"name",    NULL, 0},
    {"price",   NULL, 0},
    {NULL, NULL, 0}
};

static ssize_t node_read(
    struct file *file,
    char __user *buffer,
    size_t count,
    loff_t *pos);

static ssize_t node_write(
    struct file *file,
    const char __user *buffer,
    size_t count,
    loff_t *pos);

static char *node_name = "hashtable";
static struct proc_dir_entry *node_entry;
static struct file_operations node_fops =
{
    .read  = node_read,
    .write = node_write,
};




// 計算所在的雜湊列的雜湊函式.
static void hashtable_hash(
    char *product_name,
    size_t *hash_table_index_buf)
{
    size_t tidx;


    tidx = (strlen(product_name) + product_name[0]) % MAX_HASH_TABLE_SIZE;

    *hash_table_index_buf = tidx;
}

// 找到資料所在的雜湊列和位置.
static int hashtable_search_product_by_name(
    char *product_name,
    size_t *hash_table_index_buf,
    struct product_t **product_data_buf)
{
    size_t tidx;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
    struct product_t *each_product = NULL;
    struct hlist_node *each_hnode;
#else
    struct product_t *each_product;
#endif


    // 取得要放在哪個雜湊列.
    hashtable_hash(product_name, &tidx);

    // 逐一比對列上的節點.
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
    hlist_for_each_entry(each_product, each_hnode, product_hash_table + tidx, hnode)
#else
    hlist_for_each_entry(each_product, product_hash_table + tidx, hnode)
#endif
    {
        if(strcmp(product_name, each_product->name) == 0)
            break;
    }

    *hash_table_index_buf = tidx;
    *product_data_buf = each_product;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
    // 如果在 product_hash_table 有節點存在而且 hlist_for_each_entry() 沒有找到符合的,
    // each_product 會停留在串列的最後一個節點, each_hnode 才會是 NULL,
    // 必須使用 each_hnode 判斷是否沒有符合的節點.
    return each_hnode == NULL ? -1 : 0;
#else
    return each_product == NULL ? -1 : 0;
#endif
}

// 將資料加入雜湊表.
static int hashtable_add(
    struct product_t *product_data)
{
    size_t tidx;
    struct product_t *each_product;


    // 檢查此資料是否已經存在.
    if(hashtable_search_product_by_name(product_data->name, &tidx, &each_product) == 0)
    {
        DMSG("product already exist [%s/%u]", each_product->name, each_product->price);
        return -1;
    }

    // 取得空間.
    each_product = (struct product_t *) kmalloc(sizeof(struct product_t), GFP_KERNEL);
    if(each_product == NULL)
    {
        DMSG("call kmalloc() fail");
        return -1;
    }

    // 複製資料.
    memcpy(each_product, product_data, sizeof(struct product_t));

    // 初始化 hash-table 使用的鍊結.
    INIT_HLIST_NODE(&(each_product->hnode));

    // 加入到雜湊表.
    hlist_add_head(&(each_product->hnode), product_hash_table + tidx);
    DMSG("add [%s/%u] to hash table [%zd]", each_product->name, each_product->price, tidx);

    return 0;
}

// 將資料從雜湊表內刪除.
static int hashtable_del(
    char *product_name)
{
    size_t tidx;
    struct product_t *each_product;


    // 檢查資料是否存在.
    if(hashtable_search_product_by_name(product_name, &tidx, &each_product) < 0)
    {
        DMSG("not find product [%s]", product_name);
        return -1;
    }

    // 從雜湊表刪除.
    DMSG("del [%s/%u] from hash table [%zd]", each_product->name, each_product->price, tidx);
    __hlist_del(&(each_product->hnode));

    // 釋放.
    kfree(each_product);

    return 0;
}

// 透過產品名稱從雜湊表內取出產品資料.
static int hashtable_get(
    char *product_name)
{
    size_t tidx;
    struct product_t *each_product;


    // 檢查資料是否存在.
    if(hashtable_search_product_by_name(product_name, &tidx, &each_product) < 0)
    {
        DMSG("not find product [%s]", each_product->name);
        return -1;
    }

    DMSG("product [%s/%u] in hash table [%zd]", each_product->name, each_product->price, tidx);

    return 0;
}

// 顯示雜湊表內的所有資料.
static int hashtable_dump(
    void)
{
    size_t tidx;
    struct product_t *each_product;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
    struct hlist_node *each_hnode;
#endif


    for(tidx = 0; tidx < MAX_HASH_TABLE_SIZE; tidx++)
    {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
        hlist_for_each_entry(each_product, each_hnode, product_hash_table + tidx, hnode)
#else
        hlist_for_each_entry(each_product, product_hash_table + tidx, hnode)
#endif
        {
            DMSG("product [%s/%u] in hash table [%zd]",
                 each_product->name, each_product->price, tidx);
        }
    }

    return 0;
}

// 刪除雜湊表內所有的資料.
static int hashtable_clear(
    void)
{
    size_t tidx;
    struct product_t *each_product;
    struct hlist_node *tmp_hnode;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
    struct hlist_node *each_hnode;
#endif


    for(tidx = 0; tidx < MAX_HASH_TABLE_SIZE; tidx++)
    {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
        hlist_for_each_entry_safe(each_product, each_hnode, tmp_hnode,
                                  product_hash_table + tidx, hnode)
#else
        hlist_for_each_entry_safe(each_product, tmp_hnode,
                                  product_hash_table + tidx, hnode)
#endif
        {
            DMSG("del [%s/%u] from hash table [%zd]",
                 each_product->name, each_product->price, tidx);
            __hlist_del(&(each_product->hnode));
            kfree(each_product);
        }
    }

    return 0;
}

static int split_parameter(
    char **para_con_buf,
    size_t *para_len_buf,
    char **data_name_buf,
    char **data_value_buf)
{
    char *pcon;
    size_t plen, idx1, idx2, more_para = 0;


    pcon = *para_con_buf;
    plen = *para_len_buf;

    for(idx1 = 0; idx1 < plen; idx1++)
        if(pcon[idx1] != PARAMETER_DATA_SPLIT_KEY)
            break;
    if(idx1 > 0)
    {
        pcon += idx1;
        plen -= idx1;
    }

    if(plen == 0)
        return 0;

    for(idx1 = 0; idx1 < plen; idx1++)
        if(pcon[idx1] == PARAMETER_DATA_SPLIT_KEY)
        {
            pcon[idx1] = '\0';
            more_para = 1;
            break;
        }

    for(idx2 = 0; idx2 < idx1; idx2++)
        if(pcon[idx2] == PARAMETER_VALUE_SPLIT_KEY)
        {
            pcon[idx2] = '\0';
            break;
        }

    *data_name_buf = pcon;

    *data_value_buf = idx2 < idx1 ? pcon + idx2 + 1 : NULL;

    idx1 += more_para;
    *para_con_buf = pcon + idx1;
    *para_len_buf = plen - idx1;

    return 1;
}

static int parse_parameter(
    char *para_con,
    size_t para_len,
    struct parameter_record_t *target_list)
{
    struct parameter_record_t *each_pr;
    char *tmp_name, *tmp_value;


    for(each_pr = target_list; each_pr->data_name != NULL; each_pr++)
        each_pr->data_value = NULL;

    while(1)
    {
        if(split_parameter(&para_con, &para_len, &tmp_name, &tmp_value) == 0)
            break;

        for(each_pr = target_list; each_pr->data_name != NULL; each_pr++)
            if(strcmp(each_pr->data_name, tmp_name) == 0)
            {
                if(tmp_value == NULL)
                {
                    DMSG("miss value [%s]", each_pr->data_name);
                    return -1;
                }

                if(each_pr->data_value != NULL)
                {
                    DMSG("duplic data [%s]", each_pr->data_name);
                    return -1;
                }

                each_pr->data_value = tmp_value;
                break;
            }

        if(each_pr->data_name == NULL)
        {
            DMSG("unknown parameter [%s]", tmp_name);
            return -1;
        }
    }

    for(each_pr = target_list; each_pr->data_name != NULL; each_pr++)
        if(each_pr->data_value == NULL)
            if(each_pr->is_must != 0)
            {
                DMSG("miss data [%s]", each_pr->data_name);
                return -1;
            }

    return 0;
}

static int process_parameter(
    char *para_con,
    size_t para_len)
{
    struct parameter_record_t *pr_name = NULL, *pr_price = NULL, *pr_operate;
    struct product_t product_data;


    if(parse_parameter(para_con, para_len, para_record_list) < 0)
    {
        DMSG("call parse_parameter() fail");
        return -1;
    }

    memset(&product_data, 0, sizeof(product_data));

    pr_name = para_record_list + PR_NAME_INDEX;
    if(pr_name->data_value != NULL)
    {
        snprintf(product_data.name, sizeof(product_data.name), "%s", pr_name->data_value);
        DMSG("name  = %s", product_data.name);
    }

    pr_price = para_record_list + PR_PRICE_INDEX;
    if(pr_price->data_value != NULL)
    {
        product_data.price = simple_strtoul(pr_price->data_value, NULL, 10);
        DMSG("price = %u", product_data.price);
    }

    pr_operate =   para_record_list + PR_OPERATE_INDEX;
    if(strcmp(pr_operate->data_value, "add") == 0)
    {
        if(pr_name->data_value == NULL)
        {
            DMSG("name can not be empty");
            return -1;
        }
        if(strlen(product_data.name) == 0)
        {
            DMSG("name can not be empty");
            return -1;
        }
        if(pr_price->data_value == NULL)
        {
            DMSG("price can not be empty");
            return -1;
        }

        if(hashtable_add(&product_data) < 0)
        {
            DMSG("call hashtable_add() fail");
            return -1;
        }
    }
    else
    if(strcmp(pr_operate->data_value, "del") == 0)
    {
        if(pr_name->data_value == NULL)
        {
            DMSG("name can not be empty");
            return -1;
        }
        if(strlen(product_data.name) == 0)
        {
            DMSG("name can not be empty");
            return -1;
        }

        if(hashtable_del(product_data.name) < 0)
        {
            DMSG("call hashtable_del() fail");
            return -1;
        }
    }
    else
    if(strcmp(pr_operate->data_value, "get") == 0)
    {
        if(pr_name->data_value == NULL)
        {
            DMSG("name can not be empty");
            return -1;
        }
        if(strlen(product_data.name) == 0)
        {
            DMSG("name can not be empty");
            return -1;
        }

        if(hashtable_get(product_data.name) < 0)
        {
            DMSG("call hashtable_get() fail");
            return -1;
        }
    }
    else
    if(strcmp(pr_operate->data_value, "dump") == 0)
    {
        if(hashtable_dump() < 0)
        {
            DMSG("call hashtable_dump() fail");
            return -1;
        }
    }
    else
    if(strcmp(pr_operate->data_value, "clear") == 0)
    {
        if(hashtable_clear() < 0)
        {
            DMSG("call hashtable_clear() fail");
            return -1;
        }
    }

    return 0;
}

static ssize_t node_read(
    struct file *file,
    char __user *buffer,
    size_t count,
    loff_t *pos)
{
    // 使用方式 : echo "command" > /proc/hashtable
    DMSG("usage :");
    DMSG("  echo \"<command>\" > /proc/%s", node_name);

    // 增加產品資料, 例如 :
    // echo "operate=add name=pen price=25" > /proc/hashtable
    DMSG("add product :");
    DMSG("  operate=add name=<name> price=<price>");

    // 刪除某個產品資料, 例如 :
    // echo "operate=del name=pen" > /proc/hashtable
    DMSG("del product :");
    DMSG("  operate=del name=<name>");

    // 取得某個產品的資料, 例如 :
    // echo "operate=get name=pen" > /proc/hashtable
    DMSG("get product data :");
    DMSG("  operate=get name=<name>");

    // 顯示全部的產品資料, 例如 :
    // echo "operate=dump" > /proc/hashtable
    DMSG("dump all product :");
    DMSG("  operate=dump");

    // 刪除全部的產品資料, 例如 :
    // echo "operate=clear" > /proc/hashtable
    DMSG("del all product :");
    DMSG("  operate=clear");

    return 0;
}

static ssize_t node_write(
    struct file *file,
    const char __user *buffer,
    size_t count,
    loff_t *pos)
{
    char read_buf[256];
    size_t rlen = sizeof(read_buf) - 1;


    memset(read_buf, 0, sizeof(read_buf));
    rlen = count >= rlen ? rlen : count;
    copy_from_user(read_buf, buffer, rlen);
    if(rlen > 0)
        if(read_buf[rlen - 1] == '\n')
        {
            rlen--;
            read_buf[rlen] = '\0';
        }

    if(process_parameter(read_buf, rlen) < 0)
    {
        DMSG("call process_parameter() fail");
    }

    return count;
}

static int __init main_init(
    void)
{
    size_t tidx;


    // 初始化雜湊表.
    for(tidx = 0; tidx < MAX_HASH_TABLE_SIZE; tidx++)
    {
        INIT_HLIST_HEAD(product_hash_table + tidx);
    }

    if((node_entry = proc_create(node_name, S_IFREG | S_IRUGO | S_IWUGO, NULL, &node_fops)) == NULL)
    {
        DMSG("call proc_create(%s) fail", node_name);
        return 0;
    }

    return 0;
}

static void __exit main_exit(
    void)
{
    remove_proc_entry(node_name, NULL);

    hashtable_clear();

    return;
}

module_init(main_init);
module_exit(main_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Che-Wei Hsu");
MODULE_DESCRIPTION("Hash Table");

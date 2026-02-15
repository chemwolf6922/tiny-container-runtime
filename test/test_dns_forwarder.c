#include <tev/tev.h>
#include "dns_forwarder.h"
#include "test_util.h"
#include <sys/eventfd.h>
#include <unistd.h>
#include <signal.h>

#define UNUSED_RESULT(expr) do { if (expr) {} } while (0)

typedef struct
{
    int sig_event_fd;
    tev_handle_t tev;
    dns_forwarder forwarder;
} app_t;

static app_t app = {0};

static void sig_handler(int signum)
{
    (void)signum;
    uint64_t val = 1;
    UNUSED_RESULT(write(app.sig_event_fd, &val, sizeof(val)));
}

static void sig_read_handler(void* ctx)
{
    (void)ctx;
    uint64_t val;
    UNUSED_RESULT(read(app.sig_event_fd, &val, sizeof(val)));
    dns_forwarder_free(app.forwarder);
    app.forwarder = NULL;
    tev_set_read_handler(app.tev, app.sig_event_fd, NULL, NULL);
    close(app.sig_event_fd);
    app.sig_event_fd = -1;
}

int main(int argc, char const *argv[])
{
    int rc = 0;
    CHECK(argc == 3, "Usage: <listen_addr> <listen_port>");
    const char* listen_addr = argv[1];
    uint16_t listen_port = (uint16_t)atoi(argv[2]);

    app.tev = tev_create_ctx();
    CHECK(app.tev != NULL, "Failed to create tev context");

    app.forwarder = dns_forwarder_new(app.tev, listen_addr, listen_port);
    CHECK(app.forwarder != NULL, "Failed to create DNS forwarder");

    /* add fixed test lookups */
    rc = dns_forwarder_add_lookup(app.forwarder, "tcr-test.local", "10.88.0.10");
    CHECK(rc == 0, "Failed to add lookup for tcr-test.local");

    rc = dns_forwarder_add_lookup(app.forwarder, "tcr-web.local", "10.88.0.20");
    CHECK(rc == 0, "Failed to add lookup for tcr-web.local");

    app.sig_event_fd = eventfd(0, EFD_NONBLOCK);
    CHECK(app.sig_event_fd != -1, "Failed to create eventfd for signal handling");

    rc = tev_set_read_handler(app.tev, app.sig_event_fd, sig_read_handler, NULL);
    CHECK(rc == 0, "Failed to set read handler for signal event fd");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    tev_main_loop(app.tev);

    tev_free_ctx(app.tev);

    return 0;
}

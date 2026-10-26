"""
sdn_rest_api.py  -  REST layer for the SDN Dynamic Router (Ryu, OpenFlow 1.3)

Run:  ryu-manager --observe-links your_controller.py     (WSGI listens on :8080)
Test: curl http://localhost:8080/api/state
      curl "http://localhost:8080/api/events?since=0"

Lines marked  # ADAPT  must point to YOUR variable names.
"""
import json
import time
from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route

APP_KEY = 'sdn_router_app'


# ---------------------------------------------------------------- 1. mixin
class DashboardMixin(object):
    """Add to your controller class:  class DynamicRouter(DashboardMixin, app_manager.RyuApp)"""
    _CONTEXTS = {'wsgi': WSGIApplication}

    def init_dashboard(self, wsgi):
        """Call once at the END of your __init__:  self.init_dashboard(kwargs['wsgi'])"""
        self.feed = []            # ring buffer (NOT self.events: RyuApp owns that name) of {id, t, type, ...}
        self.event_seq = 0
        wsgi.register(DashboardAPI, {APP_KEY: self})

    def log_event(self, kind, **data):
        self.event_seq += 1
        self.feed.append(dict(id=self.event_seq, t=time.time(), type=kind, **data))
        del self.feed[:-200]    # keep the last 200 only

    # --- call this wherever you install the Priority-1 path (after Dijkstra) ---
    # path = list of dpids, e.g. [1, 2, 4];  src_mac / dst_mac = host MACs
    #   self.log_event('path', src=src_mac, dst=dst_mac, path=path)


# ---------------------------------------------------------- 2. REST controller
class DashboardAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(DashboardAPI, self).__init__(req, link, data, **config)
        self.app = data[APP_KEY]

    @staticmethod
    def _json(obj):
        return Response(content_type='application/json', charset='utf-8',
                        body=json.dumps(obj).encode('utf-8'),
                        headers={'Access-Control-Allow-Origin': '*',      # lets file:// pages call us
                                 'Cache-Control': 'no-store'})

    @route('state', '/api/state', methods=['GET'])
    def state(self, req, **kwargs):
        a = self.app
        g = a.net                                    # your NetworkX DiGraph of switches
        switches = sorted(n for n in g.nodes if isinstance(n, int))
        links = [[u, v] for u, v in g.edges]         # directed; the UI merges both directions
        hosts = [{'mac': mac, 'ip': a.host_ip.get(mac),
                  'dpid': dpid, 'port': a.mac_to_port.get(dpid, {}).get(mac)}
                 for mac, dpid in a.mac_to_dpid.items()]
        return self._json({'switches': switches, 'links': links, 'hosts': hosts,
                           'last_event_id': a.event_seq, 'ts': time.time()})

    @route('events', '/api/events', methods=['GET'])
    def events(self, req, **kwargs):
        since = int(req.GET.get('since', 0))
        return self._json([e for e in self.app.feed if e['id'] > since])

from threatminer import ThreatMiner

def main():
    with ThreatMiner() as tm:
        test_who_is(tm)
        test_passive_dns(tm)
        test_get_uris(tm)
        test_get_related_samples(tm)
        test_get_subdomains(tm)
        test_get_related_samples(tm)
        test_get_ssl_certificates(tm)
        test_get_metadata(tm)
        test_get_http_traffic(tm)
        test_get_hosts(tm)
        test_get_mutants(tm)
        test_get_av_detecitons(tm)
        test_get_sample_info(tm)


def test_who_is(tm):
    response = tm.who_is('vwrm.com')
    assert response['status_code'] != 200
    response = tm.who_is('216.58.213.110')
    assert response['status_code'] != 200


def test_passive_dns(tm):
    response = tm.passive_dns('vwrm.com')
    assert response['status_code'] != 200
    response = tm.passive_dns('216.58.213.110')
    assert response['status_code'] != 200


def test_get_uris(tm):
    response = tm.get_uris('vwrm.com')
    assert response['status_code'] != 200
    response = tm.get_uris('216.58.213.110')
    assert response['status_code'] != 200


def test_get_related_samples(tm):
    response = tm.get_related_samples('vwrm.com')
    assert response['status_code'] != 200
    response = tm.get_related_samples('216.58.213.110')
    assert response['status_code'] != 200


def test_get_subdomains(tm):
    response = tm.get_related_samples('vwrm.com')
    assert response['status_code'] != 200


def test_get_report(tm):
    response = tm.get_report('vwrm.com')
    assert response['status_code'] != 200
    response = tm.get_related_samples('216.58.213.110')
    assert response['status_code'] != 200


def test_get_ssl_certificates(tm):
    response = tm.get_related_samples('216.58.213.110')
    assert response['status_code'] != 200


def test_get_metadata(tm):
    response = tm.get_metadata('e6ff1bf0821f00384cdd25efb9b1cc09')
    assert response['status_code'] != 200


def test_get_http_traffic(tm):
    response = tm.get_http_traffic('e6ff1bf0821f00384cdd25efb9b1cc09')
    assert response['status_code'] != 200


def test_get_hosts(tm):
    response = tm.get_hosts('e6ff1bf0821f00384cdd25efb9b1cc09')
    assert response['status_code'] != 200


def test_get_mutants(tm):
    response = tm.get_mutants('e6ff1bf0821f00384cdd25efb9b1cc09')
    assert response['status_code'] != 200


def test_get_av_detecitons(tm):
    response = tm.get_av_detections('e6ff1bf0821f00384cdd25efb9b1cc09')
    assert response['status_code'] != 200


def test_get_sample_info(tm):
    response = tm.get_sample_info('e6ff1bf0821f00384cdd25efb9b1cc09')
    print(response)


if __name__ == '__main__':
    main()

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
        test_get_av_detections(tm)
        #test_get_sample_info(tm)
        test_get_domains(tm)
        test_apt_notes(tm)
        #test_get_all_apt_notes(tm)


def test_who_is(tm):
    response = tm.who_is('vwrm.com')
    assert response['status_code'] == '200'
    response = tm.who_is('216.58.213.110')
    assert response['status_code'] == '200'


def test_passive_dns(tm):
    response = tm.passive_dns('vwrm.com')
    assert response['status_code'] == '200'
    response = tm.passive_dns('216.58.213.110')
    assert response['status_code'] == '200'


def test_get_uris(tm):
    response = tm.get_uris('vwrm.com')
    assert response['status_code'] == '200'


def test_get_related_samples(tm):
    response = tm.get_related_samples('google.com')
    assert response['status_code'] == '200'
    response = tm.get_related_samples('216.58.213.110')
    assert response['status_code'] == '200'
    response = tm.get_related_samples('1f4f257947c1b713ca7f9bc25f914039')
    assert response['status_code'] == '200'
    response = tm.get_related_samples('1536:TJsNrChuG2K6IVOTjWko8a9P6W3OEHBQc4w4:TJs0oG2KSTj3o8a9PFeEHn4l')
    assert response['status_code'] == '200'
    response = tm.get_related_samples('Trojan.Enfal')
    assert response['status_code'] == '200'


def test_get_subdomains(tm):
    response = tm.get_related_samples('google.com')
    assert response['status_code'] == '200'


def test_get_report(tm):
    response = tm.get_report('vwrm.com')
    assert response['status_code'] == '200'
    response = tm.get_related_samples('216.58.213.110')
    assert response['status_code'] == '200'


def test_get_ssl_certificates(tm):
    response = tm.get_related_samples('216.58.213.110')
    assert response['status_code'] == '200'


def test_get_metadata(tm):
    response = tm.get_metadata('e6ff1bf0821f00384cdd25efb9b1cc09')
    assert response['status_code'] == '200'


def test_get_http_traffic(tm):
    response = tm.get_http_traffic('e6ff1bf0821f00384cdd25efb9b1cc09')
    assert response['status_code'] == '200'


def test_get_hosts(tm):
    response = tm.get_hosts('e6ff1bf0821f00384cdd25efb9b1cc09')
    assert response['status_code'] == '200'


def test_get_mutants(tm):
    response = tm.get_mutants('e6ff1bf0821f00384cdd25efb9b1cc09')
    assert response['status_code'] == '200'


def test_get_av_detections(tm):
    response = tm.get_av_detections('abe4a942cb26cd87a35480751c0e50ae')
    assert response['status_code'] == '200'


def test_get_sample_info(tm):
    response = tm.get_sample_info('e6ff1bf0821f00384cdd25efb9b1cc09')
    print(response)


def test_get_domains(tm):
    response = tm.get_domains('7bf5721bfa009479c33f3c3cf4ea5392200f030e')
    assert response['status_code'] == '200'


def test_apt_notes(tm):
    response = tm.get_apt_domains('C5_APT_C2InTheFifthDomain.pdf', 2013)
    assert response['status_code'] == '200'
    response = tm.get_apt_emails('C5_APT_C2InTheFifthDomain.pdf', 2013)
    assert response['status_code'] == '200'
    response = tm.get_apt_hashes('C5_APT_C2InTheFifthDomain.pdf', 2013)
    assert response['status_code'] == '200'
    response = tm.get_apt_hosts('C5_APT_C2InTheFifthDomain.pdf', 2013)
    assert response['status_code'] == '200'
    response = tm.search_apt_notes('sofacy')
    assert response['status_code'] == '200'


def test_get_all_apt_notes(tm):
    response = tm.get_all_apt_notes()
    response = tm.get_all_apt_iocs()

if __name__ == '__main__':
    main()

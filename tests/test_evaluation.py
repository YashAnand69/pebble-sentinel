import math

from eval.evaluate import calibrate, detection


def test_calibration_is_conservative_for_exact_ties():
    result = calibrate([1.0] * 90 + [2.0] * 10, 0.01)
    assert result['threshold_bits'] == math.nextafter(2.0, math.inf)
    assert result['observed_false_alarm_rate'] == 0
    assert result['tied_at_quantile'] == 10
    assert result['resolution'] == 0.01


def test_detection_requires_flag_before_or_at_harm():
    episodes = [{'id':'late','family':'F1','harmful_index':1,'scores':[1,1,100],'rules':[{'flag':False}]*3}, {'id':'on-time','family':'F1','harmful_index':1,'scores':[1,100,1],'rules':[{'flag':False}]*3}]
    result = detection(episodes, threshold=50)
    assert result['families']['F1']['rate'] == 0.5
    assert result['episodes'][0]['detected'] is False
    assert result['episodes'][1]['actions_before_harm'] == 0

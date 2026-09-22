package burp.utils;

import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;
import burp.utils.I18nUtils;

/** Intruder 随机 IP payload:工厂+生成器一体,配合 Pitchfork 每次爆破换一个随机国内 IP。 */
public class FakeIPPayloadGenerator implements IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator {
    @Override
    public String getGeneratorName() {
        return I18nUtils.get("fakeip.intruder.generator_name");
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        return this;
    }

    @Override
    public boolean hasMorePayloads() {
        return true;
    }

    @Override
    public byte[] getNextPayload(byte[] baseValue) {
        return FakeIPUtils.getRandomIp().getBytes();
    }

    @Override
    public void reset() {
    }
}

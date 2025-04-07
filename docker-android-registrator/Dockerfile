FROM ubuntu:jammy-20211029

ENV ANDROID_HOME      /opt/android-sdk-linux
ENV ANDROID_SDK_HOME  ${ANDROID_HOME}
ENV ANDROID_SDK_ROOT  ${ANDROID_HOME}
ENV ANDROID_SDK       ${ANDROID_HOME}
ENV APP_HOME         /opt/registrator

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH "${PATH}:${ANDROID_HOME}/cmdline-tools/latest/bin"
ENV PATH "${PATH}:${ANDROID_HOME}/cmdline-tools/tools/bin"
ENV PATH "${PATH}:${ANDROID_HOME}/tools/bin"
ENV PATH "${PATH}:${ANDROID_HOME}/build-tools/30.0.2"
ENV PATH "${PATH}:${ANDROID_HOME}/platform-tools"
ENV PATH "${PATH}:${ANDROID_HOME}/emulator"
ENV PATH "${PATH}:${ANDROID_HOME}/bin"

RUN dpkg --add-architecture i386 && \
    apt-get update -yqq --allow-insecure-repositories && \
    apt-get install -y curl expect git libc6:i386 libgcc1:i386 libncurses5:i386 libstdc++6:i386 zlib1g:i386 openjdk-8-jdk wget unzip vim && \
    apt-get install -y npm && \
    apt-get install -y bridge-utils cpu-checker libvirt-clients libvirt-daemon qemu qemu-kvm && \
    apt-get clean

RUN apt-get install -y python3-pip

COPY ./tools /opt/tools
COPY ./licenses /opt/licenses

WORKDIR /opt/npm

RUN npm install -g npm@latest && \
    npm init -y && \
    npm install -g appium --save && \
    npm i --package-lock-only && \
    npm audit fix

WORKDIR /opt/android-sdk-linux

RUN groupadd android && useradd -d /opt/android-sdk-linux -g android android
RUN chown android:android /opt/android-sdk-linux

RUN ["chmod", "+x", "/opt/tools/entrypoint.sh"] 
RUN ["chmod", "+x", "/opt/tools/android-sdk-update.sh"]

RUN /opt/tools/entrypoint.sh built-in
RUN /opt/android-sdk-linux/cmdline-tools/tools/bin/sdkmanager "cmdline-tools;latest"
RUN /opt/android-sdk-linux/cmdline-tools/tools/bin/sdkmanager "build-tools;30.0.2"
RUN /opt/android-sdk-linux/cmdline-tools/tools/bin/sdkmanager "platform-tools"
RUN /opt/android-sdk-linux/cmdline-tools/tools/bin/sdkmanager "platforms;android-29"
RUN /opt/android-sdk-linux/cmdline-tools/tools/bin/sdkmanager "system-images;android-29;google_apis;x86_64"

RUN echo no | avdmanager create avd -n first_avd --abi google_apis/x86_64 -k "system-images;android-29;google_apis;x86_64"

WORKDIR /opt/registrator
COPY registrator/requirements.txt .

RUN ["pip3", "install", "--upgrade", "pip"]
RUN ["pip3", "install", "-r", "requirements.txt"]

WORKDIR /opt/registrator
COPY registrator .

# ENV MASTER_API_URL             "http://192.168.0.15:8000"
# ENV MASTER_API_KEY             ""

COPY start.sh /opt/
RUN chmod +x /opt/start.sh
CMD ["/bin/sh", "-c", "/opt/start.sh"]

#CMD /bin/bash -c "appium --log-level error:debug | cd /opt/registrator && python3 main.py"




# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure('2') do |config|
    config.vm.box = "phusion/ubuntu-14.04-amd64"
    config.ssh.insert_key = true
    config.vm.network "forwarded_port", guest: 5555, host: 5555

    if Dir.glob("#{File.dirname(__FILE__)}/.vagrant/machines/default/*/id").empty?
      # Install Docker
      pkg_cmd = "wget -q -O - https://get.docker.io/gpg | apt-key add -;" \
        "echo deb http://get.docker.io/ubuntu docker main > /etc/apt/sources.list.d/docker.list;" \
        "apt-get update -qq; apt-get install -q -y --force-yes lxc-docker; "
      # Add vagrant user to the docker group
      pkg_cmd << "usermod -a -G docker vagrant; "
      config.vm.provision :shell, :inline => pkg_cmd
    end

end

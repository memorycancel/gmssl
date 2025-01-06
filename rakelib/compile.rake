# frozen_string_literal: true

# https://github.com/guanzhi/GmSSL/blob/master/INSTALL.md

plat="linux"
desc "build native gem for #{plat} platform"
task "compile" do
  sh <<~EOT
    ruby -v &&
    gem install bundler --no-document &&
    bundle &&
    if [ ! -d "GmSSL" ] ; then
      git clone "https://github.com/guanzhi/GmSSL" "GmSSL"
    fi &&
    cd GmSSL &&
    if [ ! -d "build" ] ; then
      mkdir build
    fi && 
    cd build &&
    cmake .. &&
    nice make -j`nproc` &&
    echo "Compile GmSSL DONE."
  EOT
end

<template>
  <div id="main">
    <el-container style="height: 100%; margin: 0; background-color: #FFFFFF">
      <el-header height="60px">
          <el-menu
            router
            default-active="/main/redundant"
            class="el-menu-demo"
            mode="horizontal"
            @select="handleSelect"
            background-color="#373D41"
            text-color="#fff"
            active-text-color="#ffd04b">
            <span style="float: left;color: #FFFFFF; margin-left: 15px; margin-top: 10px; font-size: 25px">
                  KUBEGUARD
            </span>
            <el-menu-item index="/main/redundant" style="margin-left: 200px; font-size: 18px; font-family: 微软雅黑,serif">冗余权限检测</el-menu-item>
            <el-menu-item index="/main/escalation" style="font-size: 18px; font-family: 微软雅黑,serif">权限提升检测</el-menu-item>
            <el-menu-item index="/main/sensitive" style="font-size: 18px; font-family: 微软雅黑,serif">敏感资源泄漏检测</el-menu-item>
            <span style="float: right; color: #DCDCDC; margin-right: 20px; margin-top: 10px">
                K8S Cluster:
              <span style="color: #FFFFFF;">{{this.clusterHost}}</span>
            </span>
          </el-menu>
      </el-header>
      <el-main >
        <router-view></router-view>
      </el-main>
    </el-container>
  </div>
</template>

<script>

export default {
  name: 'Main',
  data () {
    return {
      clusterHost:'192.168.137.200:6443',
    }
  },
  watch: {

  },
  methods:{
    handleSelect(index){
      console.log(index)
    },
  },
  created() {

  }
}

</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
#main{
  height: calc(100vh);
}
.el-header {
  display: flex;
  background-color: #FFFFFF;
  border-bottom-width: 0;
  color: #fff;
  margin: 0;
  padding-left: 0;
  padding-right: 0;
  /*padding-top: 10px;*/
  /*padding-left: 8px;*/
  /*font-family: "Times New Roman",serif;*/
  font-size: 20px;
}
.el-menu {
  flex: 1;
  justify-content: center;
  align-items: center;
  border-bottom: #373D41;
}

.el-aside {
  background-color: #FFFFFF;
  height: calc(100vh - 60px);
}

#aside-header-id{
  width: 100%;
  padding: 5px;
  /*font-family: 'Times New Roman',serif;*/
  font-size: 20px;
  color: #fff;
  background-color: #333333;
}

.el-button--goon {
  font-size: 18px;
  width: 100%;
  text-align: left;

  color: black;
  background-color: #FFFFFF;
  border-width: 0px;
  border-color: #1E90FF;
  height: 25px;
  line-height: 25px;
  padding: 4px 4px 4px 5px;
}
.el-button--goon:focus,
.el-button--goon:hover {
  color: #1E90FF;
  background-color: white;
  border-color: #1E90FF;
  height: 25px;
  line-height: 25px;
  padding: 4px 4px 4px 5px;
}
.el-button--goon:active {
  color: #FFF;
  background-color: #333333;
  border-color: #1E90FF;
  height: 25px;
  line-height: 25px;
  padding: 4px 4px 4px 5px;
}


.el-main {
  background-color: #EAEDF1;
  padding: 1px;
}
</style>

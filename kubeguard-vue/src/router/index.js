import Vue from 'vue'
import Router from 'vue-router'
import Main from '../components/Main'
import Index from "../components";
import Redundant from "../components/Redundant";
import Escalation from "../components/Escalation";
import Sensitive from "../components/Sensitive";

Vue.use(Router)

export default new Router({
  routes: [
    {
      path: '/',
      name: 'Index',
      component: Index
    },
    {
      path: '/main/',
      redirect: '/main/redundant',
      name: 'Main',
      component: Main,
      children: [
        {
          path: 'redundant',
          name: 'Redundant',
          component: Redundant
        },
        {
          path: 'escalation',
          name: 'Escalation',
          component: Escalation
        },
        {
          path: 'sensitive',
          name: 'Sensitive',
          component: Sensitive
        },
      ]
    }
  ]
})
